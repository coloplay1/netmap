"""
netmap_dnscheck.py — DNS 對帳：用 NetBIOS 問出每個 IP 上實際是哪台電腦，再和 AD 的 DNS 記錄比對。

公司常見的情況：DHCP 由防火牆派發，AD 的 DNS 不會跟著更新；電腦換了 IP 後，DNS 還指著舊 IP，
舊 IP 又被派給別台，網芳打 \\電腦名稱 就連錯台或連不到。這個模組只用標準函式庫：
  • nbstat(ip)：NetBIOS 節點狀態查詢（UDP 137），回傳電腦名稱、網域／工作群組、MAC
  • dns_query(name, server, qtype)：最小的 DNS 用戶端（UDP 53），查 A 與 PTR
  • check(ips, server, domain, extra_names)：對帳，回傳每台的狀態與說明
不需要任何帳密；只會送出一般的 NetBIOS 與 DNS 查詢。
"""
import os, random, re, socket, struct, time
from concurrent.futures import ThreadPoolExecutor


# ───────────────────────── NetBIOS ─────────────────────────
def _nb_encode(name="*"):
    raw = name.encode("ascii")[:15].ljust(15, b"\0" if name == "*" else b" ") + (b"\0")
    return bytes([32]) + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0xF))) + b"\0"


def parse_nbstat(data):
    """解析 NBSTAT 回應。回傳 {"name", "group", "mac", "names"} 或 None。"""
    try:
        if len(data) < 57: return None
        an = struct.unpack(">H", data[6:8])[0]
        if an < 1: return None
        off = 12
        if data[off] == 0x20: off += 34
        else:
            while data[off]: off += data[off] + 1
            off += 1
        typ, = struct.unpack(">H", data[off:off + 2]); off += 10   # type class ttl rdlength
        if typ != 0x21: return None
        n = data[off]; off += 1
        names = []
        for _ in range(n):
            nm = data[off:off + 15].decode("latin-1").rstrip(" \0"); suf = data[off + 15]; fl, = struct.unpack(">H", data[off + 16:off + 18])
            names.append((nm, suf, bool(fl & 0x8000))); off += 18
        mac = ":".join(f"{b:02x}" for b in data[off:off + 6]) if len(data) >= off + 6 else ""
        comp = next((nm for nm, suf, g in names if suf == 0x00 and not g), "") or next((nm for nm, suf, g in names if suf == 0x20 and not g), "")
        grp = next((nm for nm, suf, g in names if suf == 0x00 and g), "")
        if not comp: return None
        return {"name": comp.upper(), "group": grp.upper(), "mac": "" if mac in ("00:00:00:00:00:00", "") else mac, "names": names}
    except (IndexError, struct.error):
        return None


def nbstat(ip, timeout=1.2, tries=2):
    q = struct.pack(">HHHHHH", random.randint(1, 0xFFFF), 0, 1, 0, 0, 0) + _nb_encode("*") + struct.pack(">HH", 0x21, 1)
    for _ in range(tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout); s.sendto(q, (ip, 137))
            data, _a = s.recvfrom(2048)
            r = parse_nbstat(data)
            if r: return r
        except OSError:
            pass
        finally:
            s.close()
    return None


# ───────────────────────── DNS ─────────────────────────
def _dns_name(data, off):
    labels = []; jumped = False; end = off; hops = 0
    while True:
        if off >= len(data) or hops > 40: raise ValueError("bad name")
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped: end = off + 2
            off, jumped = ptr, True; hops += 1; continue
        if ln == 0:
            if not jumped: end = off + 1
            break
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace")); off += 1 + ln
    return ".".join(labels), end


def build_query(name, qtype):
    tid = random.randint(1, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        b = part.encode("idna") if part else b""
        q += bytes([len(b)]) + b
    return tid, q + b"\0" + struct.pack(">HH", qtype, 1)


def parse_answer(data, qtype):
    """回傳 (rcode, [值...])。A 回 IP 字串，PTR 回名稱。"""
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _n, off = _dns_name(data, off); off += 4
    out = []
    for _ in range(an):
        _n, off = _dns_name(data, off)
        typ, cls, ttl, rdl = struct.unpack(">HHIH", data[off:off + 10]); off += 10
        rd = data[off:off + rdl]
        if typ == 1 and qtype == 1 and rdl == 4: out.append(socket.inet_ntoa(rd))
        elif typ == 12 and qtype == 12: out.append(_dns_name(data, off)[0])
        off += rdl
    return flags & 0xF, out


def dns_query(name, server, qtype=1, timeout=1.5, port=53):
    """qtype 1＝A、12＝PTR。回傳 (狀態, [值])；狀態：ok／nx（沒有這筆）／fail（伺服器沒回應）。"""
    tid, q = build_query(name, qtype)
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout); s.sendto(q, (server, port))
            while True:
                data, _a = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid: break
            rc, vals = parse_answer(data, qtype)
            if rc == 3: return "nx", []
            if rc != 0: return "fail", []
            return ("ok" if vals else "nx"), vals
        except (OSError, ValueError, struct.error):
            pass
        finally:
            s.close()
    return "fail", []


def ptr_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


# ───────────────────────── 這台電腦的 DNS 設定 ─────────────────────────
def local_dns():
    """回傳 (DNS 伺服器清單, 網域尾碼)。Windows 讀登錄檔（不受語系影響），其他系統讀 /etc/resolv.conf。"""
    servers, domain = [], ""
    try:
        if os.name == "nt":
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            def val(k, n):
                try: return str(winreg.QueryValueEx(k, n)[0] or "")
                except OSError: return ""
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
                domain = val(k, "Domain") or val(k, "DhcpDomain")
                servers += re.findall(r"\d+\.\d+\.\d+\.\d+", val(k, "NameServer") + " " + val(k, "DhcpNameServer"))
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Interfaces") as k:
                i = 0
                while True:
                    try: sub = winreg.EnumKey(k, i); i += 1
                    except OSError: break
                    try:
                        with winreg.OpenKey(k, sub) as s:
                            servers += re.findall(r"\d+\.\d+\.\d+\.\d+", val(s, "NameServer") + " " + val(s, "DhcpNameServer"))
                            if not domain: domain = val(s, "Domain") or val(s, "DhcpDomain")
                    except OSError:
                        pass
        else:
            for line in open("/etc/resolv.conf"):
                f = line.split()
                if len(f) >= 2 and f[0] == "nameserver" and re.match(r"\d+\.\d+\.\d+\.\d+$", f[1]): servers.append(f[1])
                if len(f) >= 2 and f[0] in ("search", "domain") and not domain: domain = f[1]
    except Exception:
        pass
    servers = [x for x in dict.fromkeys(servers) if not x.startswith("127.")]
    return servers, domain.strip(".")


# ───────────────────────── 對帳 ─────────────────────────
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,14}$")


def check(ips, server, domain="", extra_names=(), workers=48, log=lambda *a: None, port=53, progress=None):
    """ips：要問的 IP；extra_names：圖上或路由器知道、但現在可能沒開機的電腦名稱（用來抓舊記錄）。
    回傳 {"rows": [...], "summary": {...}}。每列：{ip, name, group, mac, dns:[...], ptr, status, level, text}"""
    ips = [ip for ip in dict.fromkeys(ips) if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or "")]
    import threading
    lock = threading.Lock(); A, P, nb = {}, {}, {}; done = [0]

    def lookup(n):
        with lock:
            if n in A: return A[n]
        fq = f"{n}.{domain}" if domain and "." not in n else n
        st, v = dns_query(fq, server, port=port)
        if st == "nx" and fq != n:
            st2, v2 = dns_query(n, server, port=port)
            if st2 == "ok": st, v = st2, v2
        with lock: A[n] = (st, v)
        return st, v

    def job(ip):
        """一個 IP 一條龍：NetBIOS 問名稱 → 查這個名稱在 DNS 的 IP → 反查；做完馬上回報給畫面。"""
        r = nbstat(ip)
        st, v = lookup(r["name"]) if r else ("", [])
        pst, pv = dns_query(ptr_name(ip), server, 12, port=port)
        with lock:
            nb[ip] = r; P[ip] = ((pv[0].split(".")[0].upper() if pv else ""), pst); done[0] += 1; k = done[0]
        if progress:
            try: progress(k, len(ips), {"ip": ip, "name": r["name"] if r else "", "dns": v, "dnsst": st,
                                       "ok": bool(r) and st == "ok" and v == [ip]} if r else None)
            except Exception: pass
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips) or 1))) as ex:
        list(ex.map(job, ips))
    at = {ip: r for ip, r in nb.items() if r}                    # IP → NetBIOS 回應
    by_name = {}
    for ip, r in at.items(): by_name.setdefault(r["name"], []).append(ip)
    names = set(by_name) | {n.upper() for n in extra_names if n and HOST_RE.match(n)}
    with ThreadPoolExecutor(max_workers=24) as ex:
        list(ex.map(lookup, sorted(names - set(A))))
    log(f"DNS 對帳：{len(ips)} 個 IP，{len(at)} 台回應 NetBIOS，查 {len(names)} 個名稱")
    if A and all(st == "fail" for st, _ in A.values()):
        return {"error": f"DNS 伺服器 {server} 沒有回應，請確認 IP 是 AD 的 DNS 伺服器", "rows": [], "summary": {}}

    points = {}                                                   # DNS 裡指到某個 IP 的名稱
    for n, (st, v) in A.items():
        for ip in v: points.setdefault(ip, []).append(n)
    rows = []
    for n in sorted(by_name):
        for ip in by_name[n]:
            r = at[ip]; st, v = A.get(n, ("fail", [])); ptr = P.get(ip, ("", ""))[0]
            row = {"ip": ip, "name": n, "group": r["group"], "mac": r["mac"], "dns": v, "ptr": ptr}
            others = sorted(x for x in points.get(ip, []) if x != n and x in by_name)   # 沒開機的舊名稱另外列成 ghost
            if len(by_name[n]) > 1:
                row.update(status="dupname", level="bad", text=f"同一個名稱 {n} 出現在 {len(by_name[n])} 個 IP：{'、'.join(by_name[n])}（可能是同一台有兩張網卡，或兩台電腦取了一樣的名稱）")
            elif st == "fail":
                row.update(status="dnsfail", level="warn", text="DNS 伺服器沒回應這筆查詢")
            elif not v:
                row.update(status="missing", level="warn", text=f"DNS 沒有 {n} 的記錄：網芳只能靠廣播找它，常常找不到。多半是電腦沒加入網域，或 DHCP 沒給網域尾碼")
            elif ip not in v:
                who = [f"{x}（現在是 {at[x]['name']}）" if x in at and at[x]["name"] != n else x for x in v]
                row.update(status="stale", level="bad", text=f"DNS 把 {n} 指到 {'、'.join(who)}，但它實際在 {ip}——網芳打 \\\\{n} 會連錯台或連不到")
            elif len(v) > 1:
                row.update(status="multi", level="bad", text=f"DNS 有 {len(v)} 筆 {n}：{'、'.join(v)}，除了 {ip} 都是舊記錄，網芳有時會連到舊的")
            else:
                row.update(status="ok", level="ok", text="DNS 正確")
            if others and row["status"] in ("ok", "missing"):
                row["others"] = others
                row.update(status="shared", level="bad", text=f"DNS 裡還有 {'、'.join(others)} 指到 {ip}（舊記錄），網芳連那些名稱會連到 {n}")
            if ptr and ptr != n and row["level"] == "ok":
                row.update(status="ptr", level="warn", text=f"反查 {ip} 得到 {ptr}，不是 {n}（反向記錄沒更新）")
            rows.append(row)
    # 現在沒開機、但 DNS 裡還指著別人 IP 的名稱
    for n in sorted(names - set(by_name)):
        st, v = A.get(n, ("fail", []))
        for ip in v:
            if ip in at and at[ip]["name"] != n:
                rows.append({"ip": ip, "name": n, "group": "", "mac": "", "dns": v, "ptr": P.get(ip, ("", ""))[0], "status": "ghost", "level": "bad", "owner": at[ip]["name"],
                             "text": f"{n} 現在沒有回應，但 DNS 還把它指到 {ip}，而那個 IP 現在是 {at[ip]['name']}——網芳打 \\\\{n} 會連到 {at[ip]['name']}"})
    silent = [ip for ip in ips if ip not in at]
    for ip in silent:
        p = P.get(ip, ("", ""))[0]
        rows.append({"ip": ip, "name": "", "group": "", "mac": "", "dns": [], "ptr": p, "status": "nonb", "level": "info",
                     "text": "沒有回應 NetBIOS（不是 Windows、或防火牆擋了）" + (f"；DNS 反查是 {p}" if p else "")})
    lv = {"bad": 0, "warn": 1, "ok": 3, "info": 4}
    rows.sort(key=lambda r: (lv.get(r["level"], 5), tuple(int(x) for x in r["ip"].split("."))))
    summ = {k: sum(1 for r in rows if r["level"] == k) for k in ("bad", "warn", "ok", "info")}
    summ["hosts"] = len(at)
    return {"rows": rows, "summary": summ}
