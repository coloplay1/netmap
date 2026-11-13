"""netmap 流量明細收集：接收 NetFlow v5／v9、IPFIX、sFlow v5，算出「每台設備（IP）用了多少流量、連去哪裡」。

只接收、不送任何東西給設備。設備端把 NetFlow／IPFIX 收集器設成這台電腦的 IP、UDP 2055，
sFlow 收集器設成 UDP 6343 即可。資料存在 flows.db（每 5 分鐘一筆）。
"""
import ipaddress, os, socket, sqlite3, struct, threading, time

BUCKET = 300                     # 每 5 分鐘一筆
HOST_KEEP = 31 * 86400           # 每台設備的流量保存 31 天
CONV_KEEP = 3 * 86400            # 連線明細保存 3 天
CONV_TOP = 30                    # 每台設備每 5 分鐘最多記 30 個對象，其他併成「其他」

SERVICES = {
    (6, 80): "HTTP", (6, 443): "HTTPS", (17, 443): "QUIC／HTTP3", (6, 8080): "HTTP 代理", (6, 8443): "HTTPS（8443）",
    (17, 53): "DNS", (6, 53): "DNS", (6, 853): "DNS over TLS", (17, 123): "NTP", (17, 67): "DHCP", (17, 68): "DHCP",
    (6, 22): "SSH", (6, 23): "Telnet", (6, 3389): "遠端桌面 RDP", (17, 3389): "遠端桌面 RDP", (6, 5900): "VNC",
    (6, 445): "檔案分享 SMB", (6, 139): "NetBIOS", (17, 137): "NetBIOS", (17, 138): "NetBIOS", (6, 2049): "NFS",
    (6, 25): "郵件 SMTP", (6, 465): "郵件 SMTPS", (6, 587): "郵件送信", (6, 993): "郵件 IMAPS", (6, 995): "郵件 POP3S",
    (6, 143): "郵件 IMAP", (6, 110): "郵件 POP3", (6, 21): "FTP", (6, 990): "FTPS", (6, 3306): "MySQL", (6, 1433): "SQL Server",
    (6, 5432): "PostgreSQL", (6, 389): "LDAP", (6, 636): "LDAPS", (6, 88): "Kerberos", (17, 88): "Kerberos",
    (17, 161): "SNMP", (17, 162): "SNMP Trap", (17, 514): "Syslog", (17, 500): "VPN IPsec", (17, 4500): "VPN IPsec",
    (6, 1194): "OpenVPN", (17, 1194): "OpenVPN", (17, 51820): "WireGuard", (6, 1723): "VPN PPTP", (17, 1701): "VPN L2TP",
    (17, 3478): "視訊／語音（STUN）", (17, 3479): "視訊／語音", (17, 3480): "視訊／語音", (17, 3481): "視訊／語音",
    (17, 8801): "Zoom", (17, 8802): "Zoom", (6, 5060): "SIP 電話", (17, 5060): "SIP 電話", (6, 5061): "SIP 電話（TLS）",
    (6, 554): "攝影機 RTSP", (6, 8000): "攝影機／NVR", (6, 37777): "攝影機 DVR", (6, 9100): "印表機", (6, 631): "印表機 IPP",
    (6, 5223): "Apple 推播", (6, 5228): "Google 推播", (6, 1935): "直播 RTMP", (6, 6881): "BT 下載", (17, 6881): "BT 下載",
    (1, 0): "ICMP（ping）", (58, 0): "ICMPv6", (50, 0): "VPN ESP", (47, 0): "GRE",
}
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}


def service_name(proto, port):
    return SERVICES.get((proto, port)) or SERVICES.get((proto, 0)) or (f"{PROTO.get(proto, f'協定 {proto}')} {port}" if port else PROTO.get(proto, f"協定 {proto}"))


def pick_service_port(proto, sport, dport):
    if proto not in (6, 17, 132): return 0
    if (proto, dport) in SERVICES: return dport
    if (proto, sport) in SERVICES: return sport
    return min(sport, dport) if min(sport, dport) else max(sport, dport)


def is_local(ip, extra=()):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    if ip in extra: return True
    if a.is_multicast or a.is_unspecified or a.is_loopback or (a.version == 4 and int(a) == 0xFFFFFFFF): return False
    return not a.is_global


# ───────────────────────── 解析 ─────────────────────────
class FlowRecord:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "fwd", "rev", "egress", "nsrc", "ndst")

    def __init__(s, src, dst, sport=0, dport=0, proto=0, fwd=0, rev=0, egress=False, nsrc=None, ndst=None):
        s.src, s.dst, s.sport, s.dport, s.proto, s.fwd, s.rev, s.egress, s.nsrc, s.ndst = src, dst, sport, dport, proto, fwd, rev, egress, nsrc, ndst


def _ip4(b): return socket.inet_ntop(socket.AF_INET, b)
def _ip6(b): return socket.inet_ntop(socket.AF_INET6, b)
def _uint(b): return int.from_bytes(b, "big") if b else 0


class Exporter:
    """一台送資料過來的設備。"""
    def __init__(s, addr):
        s.addr = addr; s.fmt = ""; s.pkts = 0; s.flows = 0; s.bytes = 0; s.last = 0; s.first = time.time()
        s.templates = {}       # (domain, tid) → [(type, len, enterprise)] ；options: ("opt", fields, scope_n)
        s.sampling = 1; s.has_ingress = False; s.no_template = 0; s.errors = 0

    def info(s):
        return {"addr": s.addr, "fmt": s.fmt, "pkts": s.pkts, "flows": s.flows, "bytes": s.bytes, "last": int(s.last), "first": int(s.first),
                "sampling": s.sampling, "templates": len(s.templates), "waiting_template": s.no_template, "errors": s.errors}


def parse_v5(data, ex):
    if len(data) < 24: raise ValueError("v5 header too short")
    count = struct.unpack_from("!H", data, 2)[0]
    samp = struct.unpack_from("!H", data, 22)[0] & 0x3FFF
    if samp > 1: ex.sampling = samp
    out = []
    for i in range(count):
        o = 24 + i * 48
        if o + 48 > len(data): break
        src, dst = _ip4(data[o:o + 4]), _ip4(data[o + 4:o + 8])
        octets = struct.unpack_from("!I", data, o + 20)[0]
        sport, dport = struct.unpack_from("!HH", data, o + 32)
        proto = data[o + 38]
        out.append(FlowRecord(src, dst, sport, dport, proto, octets * (samp if samp > 1 else 1)))
    return out


def _decode_fields(rec, v9):
    """把 {type: bytes} 轉成 FlowRecord（不支援的就回 None）。"""
    g = rec.get
    src = _ip4(g(8)) if g(8) and len(g(8)) == 4 else _ip6(g(27)) if g(27) and len(g(27)) == 16 else None
    dst = _ip4(g(12)) if g(12) and len(g(12)) == 4 else _ip6(g(28)) if g(28) and len(g(28)) == 16 else None
    if not src or not dst: return None
    fwd = rev = 0
    if g(231) is not None or g(232) is not None:            # initiatorOctets／responderOctets（雙向連線）
        fwd, rev = _uint(g(231)), _uint(g(232))
    else:
        fwd = _uint(g(1)) if g(1) is not None else _uint(g(85)) if g(85) is not None else 0
        if g(23) is not None:
            if v9: rev = _uint(g(23))                        # NetFlow v9 OUT_BYTES：反方向（FortiGate 等一筆含雙向）
            elif g(1) is None and g(85) is None: fwd = _uint(g(23))
    nsrc = _ip4(g(225)) if g(225) and len(g(225)) == 4 else _ip6(g(281)) if g(281) and len(g(281)) == 16 else None
    ndst = _ip4(g(226)) if g(226) and len(g(226)) == 4 else _ip6(g(282)) if g(282) and len(g(282)) == 16 else None
    return FlowRecord(src, dst, _uint(g(7)), _uint(g(11)), _uint(g(4)), fwd, rev, egress=(g(61) is not None and _uint(g(61)) == 1), nsrc=nsrc, ndst=ndst)


def _options_sampling(rec, ex):
    g = rec.get
    for k in (34, 50):
        if g(k) is not None and _uint(g(k)) > 1: ex.sampling = _uint(g(k)); return
    if g(305) is not None and g(306) is not None and _uint(g(305)):
        ex.sampling = max(1, round((_uint(g(305)) + _uint(g(306))) / _uint(g(305))))


def _record_sampling(rec, ex):
    for k in (34, 50):
        v = rec.get(k)
        if v is not None and _uint(v) > 1: return _uint(v)
    return ex.sampling


def parse_v9(data, ex):
    if len(data) < 20: raise ValueError("v9 header too short")
    domain = struct.unpack_from("!I", data, 16)[0]
    return _parse_sets(data, 20, len(data), ex, domain, v9=True)


def parse_ipfix(data, ex):
    if len(data) < 16: raise ValueError("IPFIX header too short")
    ln = min(struct.unpack_from("!H", data, 2)[0], len(data))
    domain = struct.unpack_from("!I", data, 12)[0]
    return _parse_sets(data, 16, ln, ex, domain, v9=False)


def _parse_sets(data, o, end, ex, domain, v9):
    T_TMPL, T_OPT = (0, 1) if v9 else (2, 3)
    out = []
    while o + 4 <= end:
        sid, sl = struct.unpack_from("!HH", data, o)
        if sl < 4: break
        body, bend = o + 4, min(o + sl, end)
        if sid == T_TMPL:
            p = body
            while p + 4 <= bend:
                tid, n = struct.unpack_from("!HH", data, p); p += 4
                if n == 0: ex.templates.pop((domain, tid), None); continue
                fields = []
                for _ in range(n):
                    if p + 4 > bend: break
                    t, l = struct.unpack_from("!HH", data, p); p += 4; ent = 0
                    if not v9 and t & 0x8000:
                        ent = struct.unpack_from("!I", data, p)[0]; p += 4; t &= 0x7FFF
                    fields.append((t, l, ent))
                ex.templates[(domain, tid)] = ("data", fields, 0)
        elif sid == T_OPT:
            p = body
            while p + 6 <= bend:
                if v9:
                    tid, scope_len, opt_len = struct.unpack_from("!HHH", data, p); p += 6
                    fields = []
                    for _ in range((scope_len + opt_len) // 4):
                        t, l = struct.unpack_from("!HH", data, p); p += 4; fields.append((t, l, 0))
                    ex.templates[(domain, tid)] = ("opt", fields, scope_len // 4)
                else:
                    tid, n, scope_n = struct.unpack_from("!HHH", data, p); p += 6
                    fields = []
                    for _ in range(n):
                        if p + 4 > bend: break
                        t, l = struct.unpack_from("!HH", data, p); p += 4; ent = 0
                        if t & 0x8000: ent = struct.unpack_from("!I", data, p)[0]; p += 4; t &= 0x7FFF
                        fields.append((t, l, ent))
                    ex.templates[(domain, tid)] = ("opt", fields, scope_n)
                if bend - p < 6: break
        elif sid >= 256:
            tpl = ex.templates.get((domain, sid))
            if not tpl:
                ex.no_template += 1
            else:
                kind, fields, _scope = tpl
                fixed = all(l != 0xFFFF for _t, l, _e in fields)
                minlen = sum(l for _t, l, _e in fields if l != 0xFFFF) or 1
                p = body
                while p + (minlen if fixed else 1) <= bend:
                    rec = {}; ok = True
                    for t, l, ent in fields:
                        if l == 0xFFFF:
                            if p >= bend: ok = False; break
                            l = data[p]; p += 1
                            if l == 255:
                                if p + 2 > bend: ok = False; break
                                l = struct.unpack_from("!H", data, p)[0]; p += 2
                        if p + l > bend: ok = False; break
                        if not ent: rec[t] = data[p:p + l]
                        p += l
                    if not ok: break
                    if kind == "opt":
                        _options_sampling(rec, ex)
                    else:
                        r = _decode_fields(rec, v9)
                        if r:
                            m = _record_sampling(rec, ex)
                            if m > 1: r.fwd *= m; r.rev *= m
                            out.append(r)
                    if fixed and bend - p < minlen: break
        o += sl
    return out


def _parse_frame(h):
    """sFlow 取樣到的封包標頭（Ethernet）→ (src, dst, proto, sport, dport)"""
    if len(h) < 14: return None
    et = struct.unpack_from("!H", h, 12)[0]; o = 14
    while et in (0x8100, 0x88A8, 0x9100) and len(h) >= o + 4:
        et = struct.unpack_from("!H", h, o + 2)[0]; o += 4
    if et == 0x0800 and len(h) >= o + 20:
        ihl = (h[o] & 0x0F) * 4; proto = h[o + 9]
        src, dst = _ip4(h[o + 12:o + 16]), _ip4(h[o + 16:o + 20]); q = o + ihl
    elif et == 0x86DD and len(h) >= o + 40:
        proto = h[o + 6]; src, dst = _ip6(h[o + 8:o + 24]), _ip6(h[o + 24:o + 40]); q = o + 40
    else:
        return None
    sp = dp = 0
    if proto in (6, 17) and len(h) >= q + 4: sp, dp = struct.unpack_from("!HH", h, q)
    return src, dst, proto, sp, dp


def parse_sflow(data, ex):
    if len(data) < 28: raise ValueError("sFlow too short")
    ver, at = struct.unpack_from("!II", data, 0)
    if ver != 5: raise ValueError(f"sFlow v{ver} 不支援")
    o = 8 + (4 if at == 1 else 16) + 12
    n = struct.unpack_from("!I", data, o)[0]; o += 4
    out = []
    for _ in range(n):
        if o + 8 > len(data): break
        fmt, ln = struct.unpack_from("!II", data, o); o += 8; end = o + ln
        ent, f = fmt >> 12, fmt & 0xFFF
        if ent == 0 and f in (1, 3):
            p = o
            if f == 1:
                rate = struct.unpack_from("!I", data, p + 8)[0]; p += 28
            else:
                rate = struct.unpack_from("!I", data, p + 12)[0]; p += 40
            nrec = struct.unpack_from("!I", data, p)[0]; p += 4
            if rate > 1: ex.sampling = rate
            for _r in range(nrec):
                if p + 8 > end: break
                rf, rl = struct.unpack_from("!II", data, p); p += 8; rend = p + rl
                if rf == 1 and p + 16 <= rend:                       # raw packet header
                    _hp, frame_len, _strip, hl = struct.unpack_from("!IIII", data, p)
                    t = _parse_frame(data[p + 16:p + 16 + hl])
                    if t: out.append(FlowRecord(t[0], t[1], t[3], t[4], t[2], frame_len * max(1, rate)))
                elif rf in (3, 4) and p + 8 <= rend:                 # sampled IPv4 / IPv6
                    plen, proto = struct.unpack_from("!II", data, p)
                    if rf == 3 and p + 24 <= rend:
                        src, dst = _ip4(data[p + 8:p + 12]), _ip4(data[p + 12:p + 16]); sp, dp = struct.unpack_from("!II", data, p + 16)
                    elif rf == 4 and p + 48 <= rend:
                        src, dst = _ip6(data[p + 8:p + 24]), _ip6(data[p + 24:p + 40]); sp, dp = struct.unpack_from("!II", data, p + 40)
                    else:
                        src = None
                    if src: out.append(FlowRecord(src, dst, sp, dp, proto, plen * max(1, rate)))
                p = rend
        o = end
    return out


def parse_packet(data, ex, sflow_port=False):
    if len(data) < 4: raise ValueError("太短")
    if sflow_port or struct.unpack_from("!I", data, 0)[0] == 5 and len(data) > 28 and struct.unpack_from("!I", data, 4)[0] in (1, 2):
        ex.fmt = "sFlow v5"; return parse_sflow(data, ex)
    v = struct.unpack_from("!H", data, 0)[0]
    if v == 5: ex.fmt = "NetFlow v5"; return parse_v5(data, ex)
    if v == 9: ex.fmt = "NetFlow v9"; return parse_v9(data, ex)
    if v == 10: ex.fmt = "IPFIX"; return parse_ipfix(data, ex)
    raise ValueError(f"不認得的格式（版本 {v}）")


# ───────────────────────── 收集與彙整 ─────────────────────────
class FlowCollector:
    def __init__(s, data_dir, netflow_port=2055, sflow_port=6343, known_ips=None, log=None, bind="0.0.0.0"):
        s.dir = data_dir; os.makedirs(data_dir, exist_ok=True)
        s.ports = {"netflow": netflow_port, "sflow": sflow_port}; s.bind = bind
        s.known_ips = known_ips or (lambda: set())
        s.log = log or (lambda *a: None)
        s.lock = threading.RLock(); s.exporters = {}; s.socks = []; s.errors = {}
        s.acc_host = {}; s.acc_conv = {}; s.stop_ev = threading.Event(); s.running = False
        s.db = sqlite3.connect(os.path.join(data_dir, "flows.db"), check_same_thread=False)
        s.db.execute("PRAGMA journal_mode=WAL")
        s.db.execute("CREATE TABLE IF NOT EXISTS fhost(ts INTEGER, exp TEXT, ip TEXT, rx REAL, tx REAL, PRIMARY KEY(ts, exp, ip))")
        s.db.execute("CREATE TABLE IF NOT EXISTS fconv(ts INTEGER, exp TEXT, ip TEXT, peer TEXT, proto INTEGER, port INTEGER, rx REAL, tx REAL, PRIMARY KEY(ts, exp, ip, peer, proto, port))")
        s.db.execute("CREATE INDEX IF NOT EXISTS ix_fhost_ip ON fhost(ip, ts)")
        s.db.commit()
        s._local_cache = (0, set())

    # ---- 執行 ----
    def start(s):
        if s.running: return s.status()
        s.stop_ev.clear(); s.errors = {}; s.socks = []
        for kind, port in s.ports.items():
            if not port: continue
            try:
                so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                so.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                so.bind((s.bind, int(port))); so.settimeout(1.0)
                s.socks.append(so)
                threading.Thread(target=s._recv, args=(so, kind), daemon=True).start()
            except OSError as e:
                s.errors[kind] = f"UDP {port} 無法使用（{e.strerror or e}），可能被其他程式佔用"
                s.log(f"流量收集：{s.errors[kind]}")
        s.running = bool(s.socks)
        if s.running:
            threading.Thread(target=s._flusher, daemon=True).start()
            s.log("流量收集已啟動：" + "、".join(f"{'NetFlow／IPFIX' if k == 'netflow' else 'sFlow'} UDP {p}" for k, p in s.ports.items() if p and k not in s.errors))
        return s.status()

    def stop(s):
        s.stop_ev.set()
        for so in s.socks:
            try: so.close()
            except OSError: pass
        s.socks = []
        if s.running: s.flush()
        s.running = False

    def _recv(s, so, kind):
        while not s.stop_ev.is_set():
            try: data, addr = so.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            s.ingest(data, addr[0], kind == "sflow")

    def _flusher(s):
        last_purge = 0
        while not s.stop_ev.wait(30):
            s.flush()
            if time.time() - last_purge > 3600: s.purge(); last_purge = time.time()

    def locals(s):
        t, v = s._local_cache
        if time.time() - t > 30:
            try: v = set(s.known_ips() or ())
            except Exception: v = set()
            s._local_cache = (time.time(), v)
        return v

    def ingest(s, data, addr, sflow=False):
        key = addr + ("#sflow" if sflow else "")       # 同一台設備同時送 sFlow 與 NetFlow 時分開算，避免重複
        with s.lock:
            ex = s.exporters.get(key) or s.exporters.setdefault(key, Exporter(key))
            ex.pkts += 1; ex.last = time.time()
            try: recs = parse_packet(data, ex, sflow)
            except Exception as e:
                ex.errors += 1; return 0
            extra = s.locals(); ts = int(time.time()) // BUCKET * BUCKET
            for r in recs:
                if r.egress and ex.has_ingress: continue
                if not r.egress: ex.has_ingress = True
                ex.flows += 1; ex.bytes += r.fwd + r.rev
                src = r.src if is_local(r.src, extra) else (r.nsrc if r.nsrc and is_local(r.nsrc, extra) else r.src)
                dst = r.dst if is_local(r.dst, extra) else (r.ndst if r.ndst and is_local(r.ndst, extra) else r.dst)
                sl, dl = is_local(src, extra), is_local(dst, extra)
                port = pick_service_port(r.proto, r.sport, r.dport)
                if sl: s._add(ts, key, src, dst, r.proto, port, r.rev, r.fwd)
                if dl: s._add(ts, key, dst, src, r.proto, port, r.fwd, r.rev)
            return len(recs)

    def _add(s, ts, exp, ip, peer, proto, port, rx, tx):
        k = (ts, exp, ip); h = s.acc_host.get(k)
        if h: h[0] += rx; h[1] += tx
        else: s.acc_host[k] = [rx, tx]
        k2 = (ts, exp, ip, peer, proto, port); c = s.acc_conv.get(k2)
        if c: c[0] += rx; c[1] += tx
        else: s.acc_conv[k2] = [rx, tx]

    def flush(s):
        with s.lock:
            hosts, convs = s.acc_host, s.acc_conv; s.acc_host, s.acc_conv = {}, {}
        if not hosts: return
        per = {}
        for k, v in convs.items(): per.setdefault(k[:3], []).append((k, v))
        rows = []
        for key, lst in per.items():
            lst.sort(key=lambda x: -(x[1][0] + x[1][1]))
            for k, v in lst[:CONV_TOP]: rows.append((*k, v[0], v[1]))
            if len(lst) > CONV_TOP:
                rx = sum(v[0] for _k, v in lst[CONV_TOP:]); tx = sum(v[1] for _k, v in lst[CONV_TOP:])
                rows.append((*key, "", 0, 0, rx, tx))
        with s.lock:
            s.db.executemany("INSERT INTO fhost VALUES (?,?,?,?,?) ON CONFLICT(ts, exp, ip) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                             [(*k, v[0], v[1]) for k, v in hosts.items()])
            s.db.executemany("INSERT INTO fconv VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ts, exp, ip, peer, proto, port) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx", rows)
            s.db.commit()

    def purge(s):
        now = int(time.time())
        with s.lock:
            s.db.execute("DELETE FROM fhost WHERE ts < ?", (now - HOST_KEEP,))
            s.db.execute("DELETE FROM fconv WHERE ts < ?", (now - CONV_KEEP,))
            s.db.commit()

    # ---- 查詢 ----
    def status(s):
        with s.lock:
            ex = sorted((e.info() for e in s.exporters.values()), key=lambda x: -x["bytes"])
        if not ex:   # 程式重開後，從資料庫找出曾經送過資料的設備
            with s.lock:
                for exp, last in s.db.execute("SELECT exp, MAX(ts) FROM fhost GROUP BY exp"):
                    ex.append({"addr": exp, "fmt": "", "pkts": 0, "flows": 0, "bytes": 0, "last": int(last), "first": 0, "sampling": 0, "templates": 0, "waiting_template": 0, "errors": 0, "stored": True})
        return {"running": s.running, "ports": s.ports, "errors": s.errors, "exporters": ex}

    def _pick_exp(s, exp, since):
        if exp and exp != "auto": return exp
        with s.lock:
            r = s.db.execute("SELECT exp, SUM(rx+tx) b FROM fhost WHERE ts>=? GROUP BY exp ORDER BY b DESC LIMIT 1", (since,)).fetchone()
            if not r: r = s.db.execute("SELECT exp, MAX(ts) FROM fhost GROUP BY exp ORDER BY 2 DESC LIMIT 1").fetchone()
        return r[0] if r else ""

    def top(s, minutes=60, exp="auto", limit=500):
        s.flush()
        now = int(time.time()); since = (now - minutes * 60) // BUCKET * BUCKET
        e = s._pick_exp(exp, since)
        with s.lock:
            rows = s.db.execute("SELECT ip, SUM(rx), SUM(tx), MAX(ts) FROM fhost WHERE exp=? AND ts>=? GROUP BY ip ORDER BY SUM(rx+tx) DESC LIMIT ?", (e, since, limit)).fetchall()
            exps = [r[0] for r in s.db.execute("SELECT DISTINCT exp FROM fhost WHERE ts>=?", (now - 86400,))]
        secs = max(60, now - since)
        return {"exp": e, "exporters": exps, "since": since, "now": now, "seconds": secs,
                "hosts": [{"ip": ip, "rx": rx, "tx": tx, "last": last} for ip, rx, tx, last in rows],
                "total": {"rx": sum(r[1] for r in rows), "tx": sum(r[2] for r in rows)}}

    def host(s, ip, minutes=60, exp="auto", t_from=None, t_to=None):
        s.flush()
        now = int(time.time()); since = (now - minutes * 60) // BUCKET * BUCKET; until = now + BUCKET
        if t_from and t_to and t_to > t_from:
            since = int(t_from) // BUCKET * BUCKET; until = int(t_to)
        e = s._pick_exp(exp, since)
        with s.lock:
            series = s.db.execute("SELECT ts, rx, tx FROM fhost WHERE exp=? AND ip=? AND ts>=? ORDER BY ts", (e, ip, now - 33 * 3600)).fetchall()
            tot = s.db.execute("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM fhost WHERE exp=? AND ip=? AND ts>=? AND ts<?", (e, ip, since, until)).fetchone()
            peers = s.db.execute("SELECT peer, proto, port, SUM(rx), SUM(tx) FROM fconv WHERE exp=? AND ip=? AND ts>=? AND ts<? GROUP BY peer, proto, port ORDER BY SUM(rx+tx) DESC LIMIT 200",
                                 (e, ip, since, until)).fetchall()
        svc = {}
        for peer, proto, port, rx, tx in peers:
            k = (proto, port) if peer else (-1, 0); v = svc.setdefault(k, [0, 0, 0]); v[0] += rx; v[1] += tx; v[2] += 1
        cur = int(time.time()) // BUCKET * BUCKET
        pts = [[ts, rx * 8 / (min(BUCKET, max(30, now - ts)) if ts == cur else BUCKET), tx * 8 / (min(BUCKET, max(30, now - ts)) if ts == cur else BUCKET), None, None] for ts, rx, tx in series]
        return {"ip": ip, "exp": e, "since": since, "now": now, "seconds": max(60, (min(now, until) if t_from and t_to else now) - since), "range": bool(t_from and t_to), "total": {"rx": tot[0], "tx": tot[1]}, "series": {"res": BUCKET, "span": 33 * 3600, "points": pts},
                "peers": [{"peer": p, "proto": pr, "port": po, "service": service_name(pr, po) if p else "其他", "local": bool(p) and is_local(p, s.locals()), "rx": rx, "tx": tx}
                          for p, pr, po, rx, tx in peers[:40]],
                "services": sorted([{"proto": k[0], "port": k[1], "service": service_name(*k) if k[0] >= 0 else "其他", "rx": v[0], "tx": v[1], "peers": v[2]} for k, v in svc.items()],
                                   key=lambda x: -(x["rx"] + x["tx"]))[:15]}


# ───────────────────────── 測試資料（給「傳送測試資料」與自我測試用） ─────────────────────────
TEST_HOSTS = ["192.168.1.21", "192.168.1.35", "192.168.1.52", "192.168.1.66", "192.168.1.80"]
TEST_REMOTE = [("142.250.196.110", 6, 443), ("31.13.87.36", 17, 443), ("20.190.151.70", 6, 443), ("8.8.8.8", 17, 53), ("170.114.52.2", 17, 8801), ("192.168.1.10", 6, 445)]


def _test_flows(hosts, n=24, scale=1.0):
    import random
    out = []
    for i in range(n):
        h = hosts[i % len(hosts)]; rip, proto, port = random.choice(TEST_REMOTE)
        big = 1 + (len(hosts) - hosts.index(h)) * 3
        down = int(random.uniform(0.5, 1.5) * 4_000_000 * big * scale); up = int(down * random.uniform(0.05, 0.3))
        out.append((h, rip, random.randint(49152, 65000), port, proto, up, down))
    return out


def build_v5(flows):
    now = time.time(); body = b""
    for src, dst, sp, dp, proto, up, down in flows:
        for a, b, s_, d_, by in ((src, dst, sp, dp, up), (dst, src, dp, sp, down)):
            body += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton(a), socket.inet_aton(b), b"\0" * 4, 1, 2, max(1, by // 1200), by, 0, 0, s_, d_, 0, 0, proto, 0, 0, 0, 24, 24, 0)
    n = len(body) // 48
    return [struct.pack("!HHIIIIBBH", 5, min(30, n - i), 1000, int(now), 0, 1, 0, 0, 0) + body[i * 48:(i + 30) * 48]
            for i in range(0, n, 30)]


def build_v9(flows):
    """FortiGate 式：一筆含雙向（BYTES + OUT_BYTES）。"""
    tid = 300; fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (23, 8), (2, 4), (24, 4), (10, 2), (14, 2)]
    tset = struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", t, l) for t, l in fields)
    tfs = struct.pack("!HH", 0, 4 + len(tset)) + tset
    recs = b"".join(struct.pack("!4s4sHHBQQIIHH", socket.inet_aton(s_), socket.inet_aton(d_), sp, dp, pr, up, down, up // 1200 + 1, down // 1200 + 1, 2, 1)
                    for s_, d_, sp, dp, pr, up, down in flows)
    pad = (-len(recs)) % 4
    dfs = struct.pack("!HH", tid, 4 + len(recs) + pad) + recs + b"\0" * pad
    hdr = struct.pack("!HHIIII", 9, 1 + len(flows), 1000, int(time.time()), 1, 7)
    return [hdr + tfs + dfs]


def build_ipfix(flows):
    """思科 ASA／SonicWall 式：initiatorOctets／responderOctets，另含一個廠商私有欄位與可變長度欄位。"""
    tid = 400
    tset = struct.pack("!HH", tid, 9) + b"".join(struct.pack("!HH", t, l) for t, l in ((8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (231, 8), (232, 8)))
    tset += struct.pack("!HHI", 0x8000 | 101, 4, 8741) + struct.pack("!HH", 82, 0xFFFF)   # 廠商欄位 + 可變長度 interfaceName
    tfs = struct.pack("!HH", 2, 4 + len(tset)) + tset
    recs = b""
    for s_, d_, sp, dp, pr, up, down in flows:
        recs += struct.pack("!4s4sHHBQQ", socket.inet_aton(s_), socket.inet_aton(d_), sp, dp, pr, up, down) + b"\0\0\0\1" + bytes([2]) + b"X0"
    dfs = struct.pack("!HH", tid, 4 + len(recs)) + recs
    body = tfs + dfs
    return [struct.pack("!HHIII", 10, 16 + len(body), int(time.time()), 1, 9) + body]


def build_sflow(flows, rate=512):
    """交換器式：取樣封包標頭。"""
    import random
    samples = b""; n = 0
    for s_, d_, sp, dp, pr, up, down in flows:
        for a, b_, x, y, by in ((d_, s_, dp, sp, down), (s_, d_, sp, dp, up)):
            k = max(1, round(by / 1500 / rate))
            for _ in range(k):
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 1500, 0, 0, 64, pr, 0, socket.inet_aton(a), socket.inet_aton(b_))
                l4 = struct.pack("!HH", x, y) + b"\0" * 16
                frame = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x81\x00\x00\x0a\x08\x00" + ip + l4
                hl = len(frame); padf = frame + b"\0" * ((-hl) % 4)
                rec = struct.pack("!IIII", 1, 1500, 4, hl) + padf
                fs = struct.pack("!IIIIIIII", n, 3, rate, rate * 100, 0, 3, 1, 1) + struct.pack("!II", 1, len(rec)) + rec
                samples += struct.pack("!II", 1, len(fs)) + fs; n += 1
    out = []; chunks = []; cur = b""; cnt = 0; p = 0
    while p < len(samples):
        ln = struct.unpack_from("!I", samples, p + 4)[0] + 8
        cur += samples[p:p + ln]; cnt += 1; p += ln
        if cnt == 8: chunks.append((cnt, cur)); cur = b""; cnt = 0
    if cnt: chunks.append((cnt, cur))
    for i, (c, b) in enumerate(chunks):
        out.append(struct.pack("!II4sIIII", 5, 1, socket.inet_aton("192.168.1.2"), 0, i, 1000, c) + b)
    return out


def send_test(host="127.0.0.1", port=2055, kind="ipfix", hosts=None, scale=1.0):
    """送一批模擬的流量紀錄。kind：v5 / v9 / ipfix / sflow"""
    flows = _test_flows(hosts or TEST_HOSTS, scale=scale)
    pkts = {"v5": build_v5, "v9": build_v9, "ipfix": build_ipfix, "sflow": build_sflow}[kind](flows)
    so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for p in pkts: so.sendto(p, (host, port))
    finally:
        so.close()
    return len(pkts), sum(f[5] + f[6] for f in flows)
