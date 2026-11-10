# -*- coding: utf-8 -*-
"""
netmap 心跳與告警：

  ping(ip)          → 往返毫秒（float）或 None。Windows 用系統的 ICMP API（不需要系統管理員），
                      其他系統先試 ICMP socket，再退回 ping 指令，最後用 TCP 連線探測（對方回 RST 也算在線）。
  Pinger            每隔幾秒 ping 圖上所有有 IP 的設備，連續失敗 N 次才算斷線，延遲超過門檻算「延遲高」。
  send(channel, ev) 把一則事件送到 Telegram／Discord／Slack／Teams／LINE（Messaging API）／Email／自訂 Webhook。
  Notifier          背景佇列：同一段時間內的多個事件合併成一則訊息，避免整台 Switch 斷線時洗版。

LINE Notify 已於 2025-03-31 停止服務，LINE 要用官方帳號的 Messaging API（Channel access token + 收件者 ID）。
"""
import json, os, random, re, smtplib, socket, ssl, struct, subprocess, threading, time, urllib.error, urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.header import Header

_NOWIN = 0x08000000 if os.name == "nt" else 0

# ───────────────────────── ping ─────────────────────────
_win_icmp = None
def _icmp_win(ip, timeout):
    """Windows：IcmpSendEcho（iphlpapi），一般使用者就能用，不會跳出主控台視窗。"""
    global _win_icmp
    import ctypes
    from ctypes import wintypes
    if _win_icmp is None:
        lib = ctypes.windll.iphlpapi
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        lib.IcmpSendEcho.restype = wintypes.DWORD
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        _win_icmp = lib
    lib = _win_icmp
    h = lib.IcmpCreateFile()
    if not h or h == ctypes.c_void_p(-1).value: raise OSError("IcmpCreateFile failed")
    try:
        addr = struct.unpack("<I", socket.inet_aton(ip))[0]
        data = ctypes.create_string_buffer(b"netmap-ping", 11)
        buf = ctypes.create_string_buffer(256)
        t0 = time.perf_counter()
        n = lib.IcmpSendEcho(h, addr, data, 11, None, buf, 256, int(timeout * 1000))
        if not n: return None
        status, rtt = struct.unpack_from("<II", buf.raw, 4)
        if status != 0: return None
        return float(rtt) if rtt else max(0.1, (time.perf_counter() - t0) * 1000)
    finally:
        lib.IcmpCloseHandle(h)


def _cksum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF


def _icmp_sock(ip, timeout):
    """Linux／macOS：先用不需權限的 ICMP datagram socket，不行再用 raw socket（root）。"""
    last = None
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try: s = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except (PermissionError, OSError) as e: last = e; continue
        try:
            ident, seq = random.randint(1, 0xFFFF), random.randint(1, 0xFFFF)
            body = b"netmap-ping" + struct.pack("!d", time.time())
            hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
            pkt = struct.pack("!BBHHH", 8, 0, _cksum(hdr + body), ident, seq) + body
            s.settimeout(timeout); t0 = time.perf_counter(); s.sendto(pkt, (ip, 0)); end = t0 + timeout
            while True:
                left = end - time.perf_counter()
                if left <= 0: return None
                s.settimeout(left)
                try: data, src = s.recvfrom(2048)
                except socket.timeout: return None
                if src[0] != ip: continue
                if kind == socket.SOCK_RAW: data = data[(data[0] & 0x0F) * 4:]
                if len(data) >= 8 and data[0] == 0 and (kind == socket.SOCK_DGRAM or struct.unpack("!H", data[6:8])[0] == seq):
                    return max(0.05, (time.perf_counter() - t0) * 1000)
        except OSError as e:
            last = e; continue
        finally:
            s.close()
    raise OSError(f"no icmp socket: {last}")


def _ping_cmd(ip, timeout):
    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if os.name == "nt" else ["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip]
    try: r = subprocess.run(cmd, capture_output=True, timeout=timeout + 3, creationflags=_NOWIN)
    except FileNotFoundError: raise OSError("no ping command")
    except Exception: return None
    out = (r.stdout or b"").decode("utf-8", "ignore").lower()
    if "ttl=" not in out: return None
    m = re.search(r"[=<]\s*([\d.]+)\s*ms", out)
    return float(m.group(1)) if m else 1.0


TCP_PORTS = (80, 443, 22, 445, 3389, 8080, 23, 554, 9100)
def _tcp(ip, timeout):
    t0 = time.perf_counter()
    for p in TCP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(min(timeout, 0.4))
        try:
            r = s.connect_ex((ip, p))
            if r == 0 or r in (111, 10061, 61): return max(0.1, (time.perf_counter() - t0) * 1000)
        except OSError: pass
        finally: s.close()
        if time.perf_counter() - t0 > timeout * 2: break
    return None


_method = [None]   # 這台電腦能用的方法（第一次成功後記住）
def ping(ip, timeout=1.0):
    """回傳往返毫秒；沒有回應回傳 None。"""
    try: socket.inet_aton(ip)
    except OSError:
        try: ip = socket.gethostbyname(ip)
        except OSError: return None
    order = [_method[0]] if _method[0] else (["win"] if os.name == "nt" else []) + ["sock", "cmd", "tcp"]
    for m in order:
        try:
            fn = {"win": _icmp_win, "sock": _icmp_sock, "cmd": _ping_cmd, "tcp": _tcp}[m]
            r = fn(ip, timeout)
            _method[0] = m
            if r is None and m != "tcp": r = _tcp(ip, min(timeout, 0.6))   # 擋 ICMP 的設備再試一次 TCP
            return r
        except OSError:
            if _method[0] == m: _method[0] = None
            continue
    return None


def _mac_of(ip):
    """同網段：送 ARP 問這個 IP（Windows SendARP；其他系統讀 Ping 之後的 ARP 表）。有回應回傳 MAC，否則 None。
    很多電腦用防火牆擋了 Ping，但一定會回 ARP，所以這是判斷「同網段設備在不在」最可靠的方法。"""
    try:
        if os.name == "nt":
            import ctypes
            dst = ctypes.c_ulong(struct.unpack("<L", socket.inet_aton(ip))[0])
            buf = (ctypes.c_ubyte * 8)(); ln = ctypes.c_ulong(6)
            if ctypes.windll.iphlpapi.SendARP(dst, 0, ctypes.byref(buf), ctypes.byref(ln)) != 0 or ln.value < 6: return None
            mac = ":".join(f"{b:02x}" for b in list(buf)[:6])
        else:
            mac = None
            for line in open("/proc/net/arp").read().splitlines()[1:]:
                f = line.split()
                if len(f) >= 4 and f[0] == ip and f[2] == "0x2": mac = f[3].lower(); break
        return None if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac
    except Exception:
        return None

def ping_method():
    return {"win": "ICMP（Windows）", "sock": "ICMP", "cmd": "ping 指令", "tcp": "TCP 連線探測"}.get(_method[0], "尚未執行")


# ───────────────────────── 心跳 ─────────────────────────
NO_PING_TYPES = {"patch", "seat"}

class Pinger:
    """state[設備id] = {"st": up|slow|down|wait, "rtt", "since", "fails", "last", "hist": [[ts, rtt|None], ...]}"""
    def __init__(s, get_devices, settings, on_event=None, log=print, alive=None, resolve=None):
        s.get_devices, s.settings, s.on_event, s.log = get_devices, settings, on_event or (lambda ev: None), log
        s.resolve = resolve   # resolve(d, ip) -> 這次要 Ping 的 IP：DHCP 換了 IP 時跟著 MAC 或電腦名稱（DNS）走
        s.alive = alive   # alive(d, ip) -> 說明字串或 None：Ping 不通時，用其他證據（這台電腦自己、路由器用戶端清單、埠上的流量）判斷還在線
        s.state = {}; s.lock = threading.Lock()
        s.thread = None; s.stop_ev = threading.Event(); s.wake = threading.Event(); s.last = 0

    def reset(s):
        with s.lock: s.state = {}

    def _probe(s, d, ip, tmo):
        """在工作執行緒裡：先決定這次的 IP（跟著 MAC／DNS），Ping，不通再找其他在線證據（不佔用鎖）。回傳 (rtt, how, ip)。"""
        if s.resolve:
            try: ip = s.resolve(d, ip) or ip
            except Exception: pass
        if not ip: return None, None, ip
        r = ping(ip, tmo)
        if r is not None or not s.alive: return r, None, ip
        try: return None, s.alive(d, ip), ip
        except Exception: return None, None, ip

    def targets(s):
        out = []
        for d in s.get_devices():
            ip = str(d.get("ip") or "").strip().split("/")[0]
            if d.get("ping") is False or d.get("type") in NO_PING_TYPES: continue
            if not ip and not (d.get("track") == "dns" and (d.get("dnsname") or d.get("name"))): continue
            if ip and not re.match(r"^[\w.\-]+$", ip): continue
            out.append((d, ip))
        return out

    def cycle(s):
        tg = s.targets(); cfg = s.settings()
        fails_need = max(1, int(cfg.get("ping_fails") or 2)); slow = float(cfg.get("ping_slow_ms") or 200); tmo = float(cfg.get("ping_timeout") or 1.0)
        res = {}
        if tg:
            with ThreadPoolExecutor(max_workers=min(48, len(tg))) as ex:
                for (d, _ip), (rtt, how, ip) in zip(tg, ex.map(lambda x: s._probe(x[0], x[1], tmo), tg)):
                    if ip: res[d["id"]] = (d, ip, rtt, how)
        now = int(time.time()); events = []
        with s.lock:
            alive = set()
            for did, (d, ip, rtt, how) in res.items():
                alive.add(did)
                st = s.state.get(did) or {"st": "wait", "rtt": None, "since": now, "fails": 0, "hist": deque(maxlen=240), "ip": ip}
                st["ip"] = ip; st["last"] = now; st["hist"].append((now, round(rtt, 1) if rtt is not None else (-1 if how else None)))   # -1＝不回 Ping，但有其他在線證據
                prev = st["st"]; st["how"] = how
                if rtt is None and st["how"]:
                    st["fails"] = 0; st["rtt"] = None
                    new = prev if prev in ("up", "slow") else "up"
                elif rtt is None:
                    st["fails"] += 1; st["rtt"] = None
                    new = "down" if st["fails"] >= fails_need else (prev if prev != "wait" else "wait")
                else:
                    st["fails"] = 0; st["rtt"] = round(rtt, 1)
                    recent = [r for _, r in list(st["hist"])[-3:] if r is not None and r >= 0]
                    new = "slow" if recent and min(recent) >= slow else "up"
                if new != prev:
                    st["since"] = now
                    if prev != "wait" or new == "down":
                        events.append({"kind": {"down": "down", "up": "up", "slow": "slow"}[new] if not (new == "up" and prev == "slow") else "fast",
                                       "dev": did, "name": d.get("name") or ip, "ip": ip, "prev": prev, "rtt": st["rtt"], "ts": now,
                                       "down_secs": now - st.get("down_at", now) if new != "down" and prev == "down" else None})
                    if new == "down": st["down_at"] = now
                st["st"] = new
                s.state[did] = st
            for k in [k for k in s.state if k not in alive]: s.state.pop(k, None)
        s.last = now
        for ev in events:
            try: s.on_event(ev)
            except Exception as e: s.log(f"告警處理錯誤：{e}")
        return res

    def snapshot(s, hist=False):
        with s.lock:
            out = {}
            for k, v in s.state.items():
                h = list(v["hist"])
                ok = [r for _, r in h if r is not None and r >= 0]; lost = sum(1 for _, r in h if r is None); quiet = sum(1 for _, r in h if r == -1)
                o = {"st": v["st"], "rtt": v["rtt"], "since": v["since"], "last": v.get("last"), "ip": v.get("ip"), "how": v.get("how"),
                     "loss": round(100 * lost / len(h)) if h else None, "quiet": round(100 * quiet / len(h)) if h else None,
                     "avg": round(sum(ok) / len(ok), 1) if ok else None}
                if hist: o["hist"] = h[-120:]
                out[k] = o
            return out

    def run(s):
        while not s.stop_ev.is_set():
            cfg = s.settings()
            if cfg.get("ping_enabled", True):
                try: s.cycle()
                except Exception as e: s.log(f"Ping 錯誤：{e}")
            s.wake.wait(max(5, int(cfg.get("ping_interval") or 30))); s.wake.clear()

    def start(s):
        if s.thread and s.thread.is_alive(): return
        s.stop_ev.clear(); s.thread = threading.Thread(target=s.run, daemon=True, name="pinger"); s.thread.start()

    def stop(s): s.stop_ev.set(); s.wake.set()


# ───────────────────────── 告警訊息 ─────────────────────────
KIND_TEXT = {"down": ("🔴", "斷線"), "up": ("🟢", "恢復連線"), "slow": ("🟡", "延遲變高"), "fast": ("🟢", "延遲恢復正常"),
             "port_down": ("🔴", "埠離線"), "port_up": ("🟢", "埠恢復"), "newdev": ("🆕", "新設備加入網路"), "gone": ("⚪", "很久沒出現"),
             "ipchange": ("🔁", "IP 變更"), "test": ("✅", "測試訊息"), "snmp_down": ("🟠", "SNMP 沒有回應"), "snmp_up": ("🟢", "SNMP 恢復"), "back": ("🟢", "重新出現"), "snmp_found": ("🔎", "開始 SNMP 監控"), "drift": ("📐", "圖面和實際不符"), "dns": ("🧭", "DNS 和實際 IP 不符"), "ipconflict": ("⚠️", "IP 衝突")}
LEVEL = {"down": "bad", "port_down": "bad", "snmp_down": "warn", "slow": "warn", "newdev": "info", "gone": "warn", "ipchange": "info",
         "up": "ok", "port_up": "ok", "fast": "ok", "snmp_up": "ok", "test": "info", "back": "ok", "snmp_found": "ok", "drift": "warn", "dns": "bad", "ipconflict": "bad"}

def dur(sec):
    sec = int(sec or 0)
    if sec < 60: return f"{sec} 秒"
    if sec < 3600: return f"{sec // 60} 分鐘"
    if sec < 86400: return f"{sec // 3600} 小時 {sec % 3600 // 60} 分"
    return f"{sec // 86400} 天 {sec % 86400 // 3600} 小時"

def event_line(ev):
    ic, tx = KIND_TEXT.get(ev["kind"], ("•", ev["kind"]))
    who = ev.get("name") or ev.get("ip") or ""
    extra = []
    if ev.get("port_name"): extra.append(ev["port_name"])
    if ev.get("ip") and ev.get("ip") != who: extra.append(ev["ip"])
    if ev.get("mac"): extra.append(ev["mac"])
    if ev["kind"] in ("slow",) and ev.get("rtt"): extra.append(f"{ev['rtt']:.0f} ms")
    if ev.get("down_secs"): extra.append(f"斷線 {dur(ev['down_secs'])}")
    if ev.get("detail"): extra.append(ev["detail"])
    return f"{ic} {who} {tx}" + (f"（{'、'.join(extra)}）" if extra else "")

def compose(events, site=""):
    """把一批事件組成 (標題, 內文)。"""
    bad = [e for e in events if LEVEL.get(e["kind"]) == "bad"]
    head = f"[RackTrace{(' ' + site) if site else ''}] "
    if len(events) == 1: title = head + event_line(events[0])
    else: title = head + f"{len(events)} 則事件" + (f"，{len(bad)} 項異常" if bad else "")
    t = time.strftime("%Y-%m-%d %H:%M", time.localtime(events[0].get("ts") or time.time()))
    body = "\n".join(event_line(e) for e in events[:40]) + (f"\n…另外 {len(events) - 40} 則" if len(events) > 40 else "")
    return title, f"{body}\n時間：{t}"


# ───────────────────────── 通知管道 ─────────────────────────
CHANNELS = {
    "telegram": {"name": "Telegram", "fields": [("token", "Bot Token", True), ("chat", "Chat ID", False)]},
    "discord":  {"name": "Discord", "fields": [("url", "Webhook 網址", True)]},
    "slack":    {"name": "Slack", "fields": [("url", "Incoming Webhook 網址", True)]},
    "teams":    {"name": "Microsoft Teams", "fields": [("url", "Workflows Webhook 網址", True)]},
    "line":     {"name": "LINE（Messaging API）", "fields": [("token", "Channel access token", True), ("to", "收件者 ID（使用者或群組）", False)]},
    "email":    {"name": "Email（SMTP）", "fields": [("host", "SMTP 主機", False), ("port", "連接埠", False), ("tls", "加密", False), ("user", "帳號", False),
                                                       ("pw", "密碼", True), ("sender", "寄件者", False), ("to", "收件者（逗號分隔）", False)]},
    "webhook":  {"name": "自訂 Webhook（JSON）", "fields": [("url", "網址", True)]},
}
SECRET = {t: {k for k, _l, sec in c["fields"] if sec} for t, c in CHANNELS.items()}

TELEGRAM_API = os.environ.get("NETMAP_TELEGRAM_API", "https://api.telegram.org")
LINE_API = os.environ.get("NETMAP_LINE_API", "https://api.line.me")

def build_request(ch, title, text, events):
    """回傳 (url, headers, body bytes)；Email 回傳 None。分開寫方便測試。"""
    t = ch.get("type")
    js = lambda o: json.dumps(o, ensure_ascii=False).encode("utf-8")
    H = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "netmap-alert"}
    if t == "telegram":
        return f"{TELEGRAM_API}/bot{ch['token']}/sendMessage", H, js({"chat_id": ch.get("chat"), "text": f"{title}\n\n{text}" if len(events) > 1 else text.replace(event_line(events[0]), title, 1), "disable_web_page_preview": True})
    if t == "discord":
        return ch["url"], H, js({"content": (f"**{title}**\n{text}")[:1990], "username": "netmap"})
    if t == "slack":
        return ch["url"], H, js({"text": f"*{title}*\n{text}"})
    if t == "teams":
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4",
                "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True}] + [{"type": "TextBlock", "text": l, "wrap": True, "spacing": "Small"} for l in text.split("\n")]}
        return ch["url"], H, js({"type": "message", "text": title, "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
    if t == "line":
        H2 = dict(H); H2["Authorization"] = "Bearer " + ch.get("token", "")
        return f"{LINE_API}/v2/bot/message/push", H2, js({"to": ch.get("to"), "messages": [{"type": "text", "text": f"{title}\n{text}"[:4900]}]})
    if t == "webhook":
        return ch["url"], H, js({"source": "netmap", "title": title, "text": text, "events": events})
    return None


def send(ch, events, site="", timeout=10):
    """送出一則通知；成功回傳 None，失敗回傳錯誤訊息。"""
    title, text = compose(events, site)
    try:
        if ch.get("type") == "email":
            to = [x.strip() for x in re.split(r"[,;\s]+", ch.get("to") or "") if x.strip()]
            if not to or not ch.get("host"): return "請填 SMTP 主機與收件者"
            msg = MIMEText(text, "plain", "utf-8"); msg["Subject"] = Header(title, "utf-8"); msg["From"] = ch.get("sender") or ch.get("user") or "netmap@localhost"; msg["To"] = ", ".join(to)
            port = int(ch.get("port") or (465 if ch.get("tls") == "ssl" else 587 if ch.get("tls", "starttls") == "starttls" else 25))
            ctx = ssl.create_default_context()
            S = smtplib.SMTP_SSL(ch["host"], port, timeout=timeout, context=ctx) if ch.get("tls") == "ssl" else smtplib.SMTP(ch["host"], port, timeout=timeout)
            try:
                if ch.get("tls", "starttls") == "starttls": S.starttls(context=ctx)
                if ch.get("user"): S.login(ch["user"], ch.get("pw") or "")
                S.sendmail(msg["From"], to, msg.as_string())
            finally:
                try: S.quit()
                except Exception: pass
            return None
        req = build_request(ch, title, text, events)
        if not req: return "不支援的通知類型"
        url, headers, body = req
        if not re.match(r"^https?://", url or ""): return "網址格式不對"
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=timeout)
        r.read(); return None
    except urllib.error.HTTPError as e:
        try: detail = e.read().decode("utf-8", "ignore")[:200]
        except Exception: detail = ""
        return f"HTTP {e.code} {detail}".strip()
    except Exception as e:
        return str(e) or e.__class__.__name__


class Notifier:
    """事件先放進佇列，等 hold 秒把同一批合併送出；每個管道各自記錄最後一次結果。"""
    def __init__(s, get_cfg, resolve, log=print, hold=20):
        s.get_cfg, s.resolve, s.log, s.hold = get_cfg, resolve, log, hold   # resolve(ch) → 解開密碼後的管道設定
        s.q = []; s.lock = threading.Lock(); s.ev = threading.Event(); s.results = {}
        s.thread = threading.Thread(target=s.run, daemon=True, name="notifier"); s.thread.start()

    def wants(s, kind):
        a = s.get_cfg() or {}
        if not a.get("enabled"): return False
        on = a.get("on") or {}
        key = {"up": "down", "fast": "slow", "port_up": "port", "port_down": "port", "snmp_up": "snmp", "snmp_down": "snmp", "ipchange": "newdev", "back": "gone", "snmp_found": "snmp", "drift": "drift", "dns": "drift", "ipconflict": "ipconflict"}.get(kind, kind)
        if kind in ("up", "fast", "port_up", "snmp_up", "back") and not on.get("recover", True): return False
        return bool(on.get(key, key in ("down", "port", "ipconflict")))

    def push(s, ev):
        if not s.wants(ev["kind"]): return
        with s.lock: s.q.append(ev)
        s.ev.set()

    def run(s):
        while True:
            s.ev.wait(); time.sleep(s.hold); s.ev.clear()
            with s.lock: batch, s.q = s.q, []
            if not batch: continue
            s.deliver(batch)

    def deliver(s, batch, only=None):
        a = s.get_cfg() or {}; out = {}
        for ch in a.get("channels") or []:
            if only is not None and ch.get("id") != only: continue
            if only is None and ch.get("on") is False: continue
            err = send(s.resolve(ch), batch, a.get("site", ""))
            s.results[ch.get("id")] = {"ts": int(time.time()), "ok": err is None, "err": err}
            out[ch.get("id")] = err
            if err: s.log(f"通知送出失敗（{CHANNELS.get(ch.get('type'), {}).get('name', ch.get('type'))}）：{err}")
        return out
