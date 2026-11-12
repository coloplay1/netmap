# -*- coding: utf-8 -*-
"""
netmap 監控服務：在內網提供 RackTrace（機房線路對應圖）網頁，並定時用 SNMP 讀取每個埠的流量與上下線狀態。

  網頁        http://<這台電腦>:8080/
  API         GET  /api/project          目前的圖（含 rev、pid）
              GET  /api/projects  POST /api/projects   專案清單／切換／新增／複製／改名／刪除
              PUT  /api/project          儲存（rev 不符回 409）
              GET  /api/status           即時狀態：設備可達、每個埠 up/down、流量、使用率、錯誤
              GET  /api/history?port=..  埠的歷史流量（預設 24 小時）
              GET  /api/mrtg?port=..     MRTG 式流量圖資料（日／週／月／年）
              GET  /api/mrtg/summary     所有埠最近 24 小時的流量摘要
              GET  /api/mrtg/device?id=..&view=day|week|month|year  一台設備所有埠的流量圖
              GET  /api/flow/status | /api/flow/top?min=60 | /api/flow/host?ip=..&min=60   流量明細（NetFlow／IPFIX／sFlow）
              GET  /api/events  /api/pinghist?id=..  /api/seen  /api/revs  /api/revs/get?rev=..   事件、心跳、網路上的設備、歷史版本
              POST /api/revs/restore  /api/login  /api/logout  /api/alerts/test  /api/seen/forget
              GET|PUT /api/settings   告警、心跳、權限（管理員）
  修改用的請求（POST／PUT）都要帶 X-Netmap: 1 標頭。
"""
import base64, hashlib, hmac, http.server, json, os, re, secrets, socket, sqlite3, sys, threading, time, urllib.parse, zlib
from concurrent.futures import ThreadPoolExecutor

import netmap_snmp as ns
import netmap_sshmon as sm
import netmap_flow as nf
import netmap_alert as na
import netmap_audit as nau
import netmap_dnscheck as ndc

APP = "netmap"
# 主控台不是 UTF-8 時（英文版 Windows、輸出導到檔案）也不要因為中文訊息當掉
for _st in (sys.stdout, sys.stderr):
    try: _st.reconfigure(errors="replace")
    except Exception: pass

VERSION = "1.20.6"

# ───────────────────────── paths & secrets ─────────────────────────
MACHINE = False   # --machine：整台電腦共用的資料夾（C:\ProgramData\netmap），給「開機自動啟動、不用登入」的服務用（用 SYSTEM 執行，沒有使用者的 APPDATA）


def svc_log(m):
    """背景服務沒有視窗：把重要訊息記在 C:\\ProgramData\\netmap-service.log（不含密碼，一般使用者也能讀）；其他情況照常 print。"""
    if MACHINE and os.name == "nt":
        lf = os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "netmap-service.log")
        try:
            if os.path.getsize(lf) > 300000: os.replace(lf, lf + ".old")
        except Exception: pass
        try: open(lf, "a", encoding="utf-8").write(time.strftime("%Y-%m-%d %H:%M:%S ") + m + "\n")
        except Exception: pass
    else: print(m)

def _fix_acl(root, note=print):
    """共用資料夾的權限只留 SYSTEM 和系統管理員，底下的檔案改成繼承（修復安裝時可能弄壞的權限）。"""
    if os.name != "nt" or not MACHINE: return
    import subprocess
    try:
        for args in (["icacls", root, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/C", "/Q"], ["icacls", os.path.join(root, "*"), "/reset", "/T", "/C", "/Q"]):
            subprocess.run(args, capture_output=True, timeout=120, creationflags=0x08000000)
        note("已重設共用資料夾的權限")
    except Exception as e: note(f"重設權限失敗：{e}")

def data_dir():
    if MACHINE and os.name == "nt": base = os.environ.get("ProgramData") or r"C:\ProgramData"
    else: base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    d = os.path.join(base, APP)
    os.makedirs(d, exist_ok=True)
    return d

WEB_UPDATE_URL = "https://coloplay1.github.io/netmap/index.html"

def _page_ver(html):
    m = re.search(r"APP_VERSION='([\d.]+)'", html or "")
    return _vkey(m.group(1)) if m else (0,)

def web_override():
    """使用者按過「更新網頁」後存下來的新版網頁；比程式內建的新才會用（重新安裝新版程式後，內建的更新就自然換回內建）。"""
    try:
        p = os.path.join(data_dir(), "web", "index.html")
        if not os.path.exists(p): return None
        html = open(p, encoding="utf-8").read()
        b = web_index(); bh = open(b, encoding="utf-8").read() if b else ""
        if _page_ver(html) <= _page_ver(bh): return None
        m = re.search(r"MIN_EXE='([\d.]+)'", html)
        if m and _vkey(m.group(1)) > _vkey(VERSION): return None
        return html
    except Exception: return None

def web_update(url=None):
    """下載最新網頁。回傳 (版本字串, 錯誤)。只收 https（測試用的環境變數除外）、大小與內容都要通過檢查。"""
    import urllib.request
    url = url or os.environ.get("NETMAP_WEB_URL") or WEB_UPDATE_URL
    if not url.startswith(("https://", "file://")): return None, "網址不安全"
    try:
        raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "RackTrace/" + VERSION, "Cache-Control": "no-cache"}), timeout=25).read(8 * 1024 * 1024 + 1)
    except Exception as e: return None, f"下載失敗：{e}"
    if not (300000 < len(raw) < 8 * 1024 * 1024): return None, "下載到的檔案大小不對"
    html = raw.decode("utf-8", "replace")
    if "<title>" not in html or "APP_VERSION='" not in html or "window.NETMAP_SERVER" not in html: return None, "下載到的內容不是 RackTrace 網頁"
    b = web_index(); cur = max(_page_ver(open(b, encoding="utf-8").read()) if b else (0,), _page_ver(web_override()))
    if _page_ver(html) <= cur: return None, "已經是最新的網頁"
    m = re.search(r"MIN_EXE='([\d.]+)'", html)
    if m and _vkey(m.group(1)) > _vkey(VERSION): return None, f"新網頁需要程式 {m.group(1)} 以上（目前 {VERSION}），請先重新安裝新版 RackTrace-Setup.exe"
    d = os.path.join(data_dir(), "web"); os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, "index.html.new")
    open(tmp, "wb").write(raw); os.replace(tmp, os.path.join(d, "index.html"))
    return ".".join(map(str, _page_ver(html))), ""

def web_index():
    cands = []
    if getattr(sys, "_MEIPASS", None): cands.append(os.path.join(sys._MEIPASS, "web", "index.html"))
    here = os.path.dirname(os.path.abspath(__file__))
    cands += [os.path.join(here, "web", "index.html"), os.path.join(here, "..", "..", "index.html")]
    for c in cands:
        if os.path.exists(c): return c
    return None

def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes
    class BLOB(ctypes.Structure): _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(data, len(data))
    inp = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))); out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    # CRYPTPROTECT_LOCAL_MACHINE(4)：服務模式用「這台電腦」加密，任何帳號（包括 SYSTEM）都解得開；解密時 Windows 會自己判斷，不用旗標
    ok = fn(ctypes.byref(inp), None, None, None, None, 4 if (protect and MACHINE) else 0, ctypes.byref(out))
    if not ok: raise OSError("DPAPI failed")
    res = ctypes.string_at(out.pbData, out.cbData); ctypes.windll.kernel32.LocalFree(out.pbData); return res

def protect(text):
    """Windows：用 DPAPI 加密（只有同一個 Windows 帳號能解開）；其他系統只做編碼。"""
    if not text: return ""
    raw = text.encode("utf-8")
    if os.name == "nt":
        try: return "dpapi:" + base64.b64encode(_dpapi(raw, True)).decode()
        except Exception: pass
    return "b64:" + base64.b64encode(raw).decode()

def unprotect(val):
    if not val: return ""
    try:
        if val.startswith("dpapi:"): return _dpapi(base64.b64decode(val[6:]), False).decode("utf-8")
        if val.startswith("b64:"): return base64.b64decode(val[4:]).decode("utf-8")
    except Exception: return ""
    return val

def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); ips.add(s.getsockname()[0]); s.close()
    except Exception: pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."): ips.add(ip)
    except Exception: pass
    return sorted(ips) or ["127.0.0.1"]

def local_nics():
    """這台電腦的網卡：{名稱: {"ips": [...], "rx": 收到位元組, "tx": 送出位元組, "ie", "oe", "up", "speed"(bps)}}。需要 psutil（netmap.exe 已內含）。"""
    try:
        import psutil
    except ImportError:
        return None
    addrs, io, st = psutil.net_if_addrs(), psutil.net_io_counters(pernic=True), psutil.net_if_stats()
    out = {}
    for name, c in io.items():
        ips = [a.address.split("%")[0] for a in addrs.get(name, []) if a.family in (socket.AF_INET, socket.AF_INET6)]
        x = st.get(name)
        out[name] = {"ips": ips, "rx": c.bytes_recv, "tx": c.bytes_sent, "ie": c.errin, "oe": c.errout,
                     "up": bool(x.isup) if x else None, "speed": (x.speed or 0) * 1_000_000 if x else 0}
    return out


_self_cache = [0.0, set()]
def self_ips():
    """這台電腦所有的 IP（給「自動監控自己」比對用），快取 60 秒。"""
    if time.time() - _self_cache[0] > 60:
        nics = local_nics()
        ips = {ip for n in (nics or {}).values() for ip in n["ips"]} | set(local_ips())
        _self_cache[0], _self_cache[1] = time.time(), {ip for ip in ips if not ip.startswith("127.") and ip != "::1"}
    return _self_cache[1]


def private_ip(ip):
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", ip or ""))

_lan_cache = [0.0, []]
def same_lan(ip):
    """這個 IPv4 是否和這台電腦的某張網卡在同一個網段（才能用 ARP 確認）。"""
    import ipaddress
    if time.time() - _lan_cache[0] > 60:
        nets = []
        try:
            import psutil
            for n, al in psutil.net_if_addrs().items():
                for a in al:
                    if a.family == socket.AF_INET and a.netmask and not a.address.startswith("127."):
                        try: nets.append(ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False))
                        except ValueError: pass
        except ImportError:
            nets = [ipaddress.ip_network(f"{i}/24", strict=False) for i in self_ips() if "." in i and not i.startswith("127.")]
        _lan_cache[0], _lan_cache[1] = time.time(), [n for n in nets if n.prefixlen >= 16]
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _lan_cache[1])
    except ValueError:
        return False

_wifi_cache = [0.0, {}]
def _band_of(ch, band_txt=""):
    t = (band_txt or "").replace(" ", "")
    if t.startswith("6"): return "6G"
    if t.startswith("5"): return "5G"
    if t.startswith("2.4"): return "2.4G"
    try: c = int(ch)
    except (TypeError, ValueError): return ""
    return "2.4G" if c <= 14 else "5G" if c <= 177 else ""

def _run_text(cmd, timeout=6):
    import subprocess
    raw = subprocess.run(cmd, capture_output=True, timeout=timeout,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    for enc in ("utf-8", "cp950", "mbcs", "cp936"):
        try: return raw.decode(enc)
        except Exception: continue
    return raw.decode("latin-1")

def parse_excluded(txt):
    """netsh interface ipv4 show excludedportrange 的輸出 → [(開始, 結束)]"""
    return [(int(a), int(b)) for a, b in re.findall(r"(?m)^\s*(\d+)\s+(\d+)\b", txt or "")]

def parse_netstat_owner(txt, port):
    """netstat -ano 的輸出 → 正在聽這個埠的 PID（找不到回 None）"""
    for ln in (txt or "").splitlines():
        f = ln.split()
        if len(f) >= 5 and f[0].upper() == "TCP" and re.search(r"[:\]]" + str(port) + r"$", f[1]) and f[2].endswith(":0") and f[-1].isdigit():
            return int(f[-1])
    return None

def port_diag(port):
    """網頁埠開不起來時找原因：{"excluded": (開始, 結束) 或 None, "pid": PID, "proc": 程式名稱}"""
    r = {"excluded": None, "pid": None, "proc": ""}
    if os.name != "nt": return r
    try:
        for a, b in parse_excluded(_run_text(["netsh", "interface", "ipv4", "show", "excludedportrange", "protocol=tcp"])):
            if a <= port <= b: r["excluded"] = (a, b); break
    except Exception: pass
    try:
        pid = parse_netstat_owner(_run_text(["netstat", "-ano", "-p", "tcp"]), port) or parse_netstat_owner(_run_text(["netstat", "-ano", "-p", "tcpv6"]), port)
        if pid:
            r["pid"] = pid
            m = re.match(r'\s*"([^"]+)"', _run_text(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]))
            if m: r["proc"] = m.group(1)
    except Exception: pass
    return r

def _vkey(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", str(v or "0")))

def takeover_old(port, log=lambda m: None):
    """網頁埠被「舊版的 netmap」佔著時，把舊版結束掉讓新版接手。
    只動版本比自己舊、而且程式名稱是 netmap／RackTrace 的程式；同版或較新的不動（回傳 False，由呼叫端提示）。"""
    try:
        import urllib.request
        j = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=2).read().decode("utf-8", "replace"))
        if not (isinstance(j, dict) and j.get("ok") and j.get("version")): return False
        if _vkey(j["version"]) >= _vkey(VERSION): return False
    except Exception: return False
    pid = None
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            if c.status == "LISTEN" and c.laddr and c.laddr.port == port and c.pid: pid = c.pid; break
        if not pid: return False
        if pid == os.getpid(): return False
        pr = psutil.Process(pid)
        if not re.match(r"(netmap|racktrace)", pr.name(), re.I): return False
        log(f"埠 {port} 被舊版 netmap（v{j['version']}，PID {pid}）佔用，結束它讓新版 v{VERSION} 接手")
        pr.terminate()
        try: pr.wait(5)
        except Exception: pr.kill(); pr.wait(5)
    except Exception as e:
        log(f"無法結束舊版：{e}"); return False
    return True

def port_free(port):
    """這個埠現在能不能開（用獨佔模式試開一下就關掉）"""
    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"): so.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        so.bind(("0.0.0.0", port)); return True
    except OSError: return False
    finally: so.close()

def suggest_port(avoid=()):
    for p in (18080, 18765, 28080, 38080, 48080, 18081, 18888):
        if p not in avoid and port_free(p): return p
    return None

class WebServer(http.server.ThreadingHTTPServer):
    # Windows 上 SO_REUSEADDR 會讓兩個程式搶同一個埠（或靜默失敗），改用獨佔模式：被佔用就明確報錯
    allow_reuse_address = os.name != "nt"
    def server_bind(s):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

def wifi_nics():
    """這台電腦的無線網卡：{網卡名稱: {"band", "ssid", "radio"}}，快取 60 秒。
    Windows 讀 netsh wlan show interfaces（中英文欄位都認得），Linux 看 /sys/class/net/*/wireless。"""
    if time.time() - _wifi_cache[0] < 60: return _wifi_cache[1]
    out = {}
    try:
        if os.name == "nt":
            import subprocess
            raw = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=5,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            txt = None
            for enc in ("utf-8", "cp950", "mbcs", "cp936"):
                try: txt = raw.decode(enc); break
                except Exception: continue
            out = parse_netsh_wlan(txt or "")
        else:
            for n in os.listdir("/sys/class/net"):
                if os.path.isdir(f"/sys/class/net/{n}/wireless"): out[n] = {"band": "", "ssid": "", "radio": ""}
    except Exception:
        pass
    _wifi_cache[0], _wifi_cache[1] = time.time(), out
    return out

def parse_netsh_wlan(txt):
    out = {}; cur = None
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1); k, v = k.strip(), v.strip()
        kl = k.lower()
        if kl in ("name", "名稱", "名称"):
            cur = {"band": "", "ssid": "", "radio": "", "ch": "", "bandtxt": "", "state": ""}; out[v] = cur; continue
        if cur is None: continue
        if kl == "ssid": cur["ssid"] = v
        elif kl in ("state", "狀態", "状态"): cur["state"] = v
        elif "radio" in kl or "無線電" in k or "无线电" in k: cur["radio"] = v
        elif kl in ("channel", "通道", "頻道", "频道", "信道"): cur["ch"] = v
        elif kl in ("band", "頻帶", "频带", "頻段", "频段"): cur["bandtxt"] = v
    res = {}
    for n, c in out.items():
        st = c["state"]
        if st and (re.search(r"disconnect|中斷|中断|未連線|未连接", st, re.I) or not re.search(r"connected|已連線|已连接", st, re.I)):
            continue
        res[n] = {"band": _band_of(c["ch"], c["bandtxt"]), "ssid": c["ssid"], "radio": c["radio"]}
    return res


# ───────────────────────── store ─────────────────────────
# MRTG 的四種解析度：(每點秒數, 保存秒數) 與 (圖名, 圖上顯示的時間範圍)
ROLLUPS = [(300, 3 * 86400), (1800, 14 * 86400), (7200, 62 * 86400), (86400, 800 * 86400)]
MRTG_VIEWS = [("day", 33 * 3600), ("week", 8 * 86400), ("month", 35 * 86400), ("year", 400 * 86400)]

# 線上版網頁偵測本機 netmap.exe：只有使用者勾選才開，只回答 /api/ping，只給這台電腦自己的瀏覽器
DETECT_ORIGINS = {"https://coloplay1.github.io"}

DEFAULT_SETTINGS = {"port": 8080, "interval": 60, "retention_days": 7, "lan_edit": False, "autostart": False, "autorun": True, "web_detect": True, "web_detect_ver": 2, "monitor_self": True,
                    "flow_enabled": False, "flow_port": 2055, "sflow_port": 6343,
                    "ping_enabled": True, "ping_interval": 30, "ping_fails": 2, "ping_slow_ms": 200, "ping_timeout": 1.0,
                    "alerts": {"enabled": False, "site": "", "on": {"down": True, "recover": True, "port": True, "slow": False, "snmp": False, "newdev": False, "gone": False}, "channels": []},
                    "admin_hash": "", "view_token": "", "view_required": False, "inv_enabled": True, "inv_gone_hours": 24, "snmp_autoprobe": True, "audit_hours": 6,
                    "snmp": {"version": "2c", "community": "", "user": "", "auth_proto": "SHA", "auth_key": "", "priv_proto": "AES", "priv_key": "",
                             "context": "", "port": 161, "timeout": 2.0, "retries": 1}}

PROJECT_KEYS = ("devices", "cables", "racks", "faults", "repairs", "pages", "trunks")

def norm_mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", str(m or "")).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 and h not in ("000000000000", "ffffffffffff") else ""

def object_snapshot(pj, oid):
    """一個版本裡某台設備（含接在它埠上的線，與線另一端的名稱）或某條線。"""
    owner = {}
    for d in pj.get("devices", []):
        for p in d.get("ports", []): owner[p["id"]] = (d, p)
    nm = lambda pid: f"{owner[pid][0].get('name', '')} 埠 {owner[pid][1].get('label', '')}" if pid in owner else "?"
    d = next((x for x in pj.get("devices", []) if x.get("id") == oid), None)
    if d:
        mine = {p["id"] for p in d.get("ports", [])}
        cabs = [{"id": c["id"], "label": c.get("label", ""), "here": nm(c["a"] if c["a"] in mine else c["b"]), "there": nm(c["b"] if c["a"] in mine else c["a"])}
                for c in pj.get("cables", []) if c.get("a") in mine or c.get("b") in mine]
        dd = {k: v for k, v in d.items() if k not in ("x", "y")}
        return {"kind": "dev", "obj": dd, "cabs": sorted(cabs, key=lambda c: c["id"])}
    c = next((x for x in pj.get("cables", []) if x.get("id") == oid), None)
    if c:
        cc = {k: v for k, v in c.items() if k != "wps"}; cc["aName"] = nm(c["a"]); cc["bName"] = nm(c["b"])
        return {"kind": "cable", "obj": cc}
    return {"kind": None, "obj": None}

def diff_projects(a, b):
    """兩個版本的差異摘要：{"text": "...", "devices": {"add": [...], "del": [...], "mod": [...]}, "cables": {...}, "moved": n}"""
    da = {d["id"]: d for d in a.get("devices", []) if isinstance(d, dict) and d.get("id")}
    db = {d["id"]: d for d in b.get("devices", []) if isinstance(d, dict) and d.get("id")}
    ca = {c["id"]: c for c in a.get("cables", []) if isinstance(c, dict) and c.get("id")}
    cb = {c["id"]: c for c in b.get("cables", []) if isinstance(c, dict) and c.get("id")}
    pname = {}
    for dd in (da, db):
        for d in dd.values():
            for p in d.get("ports", []): pname[p.get("id")] = f"{d.get('name', '')} {p.get('label', '')}".strip()
    cname = lambda c: (c.get("label") or "") + f"（{pname.get(c.get('a'), '?')} ↔ {pname.get(c.get('b'), '?')}）"
    strip = lambda d, keys: {k: v for k, v in d.items() if k not in keys}
    add = [db[k].get("name", "") for k in db if k not in da]; rem = [da[k].get("name", "") for k in da if k not in db]
    mod, moved = [], 0
    for k in db:
        if k in da and da[k] != db[k]:
            if strip(da[k], ("x", "y")) == strip(db[k], ("x", "y")): moved += 1
            else: mod.append(db[k].get("name", ""))
    cadd = [cname(cb[k]) for k in cb if k not in ca]; crem = [cname(ca[k]) for k in ca if k not in cb]
    cmod, cmoved = [], 0
    for k in cb:
        if k in ca and ca[k] != cb[k]:
            if strip(ca[k], ("wps",)) == strip(cb[k], ("wps",)): cmoved += 1
            else: cmod.append(cname(cb[k]))
    other = [k for k in ("racks", "faults", "repairs", "pages", "trunks") if (a.get(k) or []) != (b.get(k) or [])]
    parts = []
    def P(n, verb, what, names):
        if n: parts.append(f"{verb}{what} {n}" + (f"（{'、'.join(x for x in names[:3] if x)}{'…' if n > 3 else ''}）" if any(names[:3]) else ""))
    P(len(add), "新增", "設備", add); P(len(rem), "刪除", "設備", rem); P(len(mod), "修改", "設備", mod)
    P(len(cadd), "接上", "線", [c.split("（")[0] or c for c in cadd]); P(len(crem), "拔掉", "線", [c.split("（")[0] or c for c in crem]); P(len(cmod), "修改", "線", [c.split("（")[0] for c in cmod])
    if moved or cmoved: parts.append("調整版面")
    names = {"racks": "機櫃", "faults": "故障紀錄", "repairs": "維修記錄", "pages": "頁面", "trunks": "光纖束"}
    if other: parts.append("修改" + "、".join(names[k] for k in other))
    return {"text": "、".join(parts) or "沒有變更", "devices": {"add": add, "del": rem, "mod": mod}, "cables": {"add": cadd, "del": crem, "mod": cmod}, "moved": moved + cmoved, "other": other}


class Store:
    def __init__(s, root=None):
        s.root = root or data_dir(); os.makedirs(s.root, exist_ok=True); s.dir = s.root; s.conflicts = {}
        s.lock = threading.RLock()
        s.settings = json.loads(json.dumps(DEFAULT_SETTINGS))
        p = os.path.join(s.root, "settings.json")
        if os.path.exists(p):
            try:
                saved = json.load(open(p, encoding="utf-8"))
                snmp = {**s.settings["snmp"], **saved.get("snmp", {})}
                s.settings.update(saved); s.settings["snmp"] = snmp
                if int(saved.get("web_detect_ver", 1) or 1) < 2:   # 舊版預設是關的，從沒有人刻意選過：升級後改成預設開（只回本機、只給版本與埠號）
                    s.settings["web_detect"] = True; s.settings["web_detect_ver"] = 2; s._migrated = True
            except Exception: pass
        if not s.settings["snmp"].get("community"): s.settings["snmp"]["community"] = protect("public")
        if getattr(s, "_migrated", False):
            try: s.save_settings()
            except Exception: pass
        s.db = None
        s.reg = s._load_reg()
        s._open(s.reg["current"])

    # ---------- 多專案：每個專案各自的圖、歷史版本、事件與流量紀錄；設定、帳密、告警是全部專案共用 ----------
    def _load_reg(s):
        reg = {"current": "default", "list": []}
        try:
            o = json.load(open(os.path.join(s.root, "projects.json"), encoding="utf-8"))
            if isinstance(o.get("list"), list): reg = {"current": o.get("current") or "default", "list": [x for x in o["list"] if isinstance(x, dict) and x.get("id")]}
        except Exception: pass
        if not any(x["id"] == "default" for x in reg["list"]): reg["list"].insert(0, {"id": "default", "name": "預設專案", "created": int(time.time())})
        if not any(x["id"] == reg["current"] for x in reg["list"]): reg["current"] = "default"
        return reg

    def _save_reg(s):
        tmp = os.path.join(s.root, "projects.json.tmp")
        json.dump(s.reg, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1); os.replace(tmp, os.path.join(s.root, "projects.json"))

    def _pdir(s, pid):
        return s.root if pid == "default" else os.path.join(s.root, "projects", pid)

    @property
    def pid(s): return s.reg["current"]

    def _open(s, pid):
        if s.db is not None:
            try: s.db.close()
            except Exception: pass
        s.dir = s._pdir(pid); os.makedirs(s.dir, exist_ok=True); s.reg["current"] = pid
        s.rev, s.project = 0, {"devices": [], "cables": [], "racks": [], "faults": []}
        pp = os.path.join(s.dir, "project.json")
        if os.path.exists(pp):
            try:
                o = json.load(open(pp, encoding="utf-8")); s.rev = int(o.get("rev", 1)); s.project = o.get("project") or s.project
            except Exception: pass
        dbp = os.path.join(s.dir, "metrics.db")
        try:
            s.db = sqlite3.connect(dbp, check_same_thread=False); s.db.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError as e:
            # 資料庫打不開（常見：權限被改壞）：先試著把共用資料夾的權限修好，再不行就把壞掉的資料庫改名另開新的，服務才起得來
            try: s.db.close()
            except Exception: pass
            _fix_acl(s.root, svc_log)
            try:
                s.db = sqlite3.connect(dbp, check_same_thread=False); s.db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                try: s.db.close()
                except Exception: pass
                bad = f"{dbp}.bad-{int(time.time())}"
                for suf in ("", "-wal", "-shm"):
                    try: os.replace(dbp + suf, bad + suf)
                    except Exception: pass
                svc_log(f"metrics.db 打不開（{e}），已改名為 {os.path.basename(bad)}，另開新的歷史資料庫")
                s.db = sqlite3.connect(dbp, check_same_thread=False); s.db.execute("PRAGMA journal_mode=WAL")
        s.db.execute("CREATE TABLE IF NOT EXISTS samples(ts INTEGER, pid TEXT, inb REAL, outb REAL, up INTEGER, ierr INTEGER, oerr INTEGER)")
        s.db.execute("CREATE INDEX IF NOT EXISTS ix_samples ON samples(pid, ts)")
        # MRTG 式彙整：每個埠在 5 分鐘／30 分鐘／2 小時／1 天的平均與最大值，保存期比原始紀錄長
        s.db.execute("CREATE TABLE IF NOT EXISTS rollup(pid TEXT, res INTEGER, ts INTEGER, n INTEGER, sin REAL, sout REAL, xin REAL, xout REAL, upn INTEGER, spd REAL, PRIMARY KEY(pid, res, ts))")
        # 事件（斷線／恢復／新設備…）、圖的歷史版本、網路上看過的設備
        s.db.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, level TEXT, dev TEXT, port TEXT, text TEXT, data TEXT)")
        s.db.execute("CREATE INDEX IF NOT EXISTS ix_events ON events(ts)")
        s.db.execute("CREATE TABLE IF NOT EXISTS revs(rev INTEGER PRIMARY KEY, ts INTEGER, who TEXT, summary TEXT, detail TEXT, data BLOB)")
        s.db.execute("CREATE TABLE IF NOT EXISTS audit(key TEXT PRIMARY KEY, kind TEXT, level TEXT, dev TEXT, port TEXT, cable TEXT, text TEXT, fix TEXT, first INTEGER, last INTEGER, status TEXT)")
        s.db.execute("CREATE TABLE IF NOT EXISTS verify(cable TEXT PRIMARY KEY, ts INTEGER, how TEXT)")
        s.db.execute("CREATE TABLE IF NOT EXISTS seen(mac TEXT PRIMARY KEY, ip TEXT, name TEXT, vendor TEXT, first INTEGER, last INTEGER, src TEXT, via TEXT, wireless INTEGER, gone INTEGER DEFAULT 0, ips TEXT)")
        s.db.commit()
        if not s.db.execute("SELECT 1 FROM revs LIMIT 1").fetchone() and s.project.get("devices"):
            s._add_rev(s.rev, s.project, None, "升級前的版本", int(time.time())); s.db.commit()
        if not s.db.execute("SELECT 1 FROM rollup LIMIT 1").fetchone() and s.db.execute("SELECT 1 FROM samples LIMIT 1").fetchone():
            for res, _ in ROLLUPS:   # 舊版升級：用現有的原始紀錄補出彙整
                s.db.execute("INSERT OR REPLACE INTO rollup SELECT pid, ?, (ts/?)*?, COUNT(*), SUM(COALESCE(inb,0)), SUM(COALESCE(outb,0)), MAX(COALESCE(inb,0)), MAX(COALESCE(outb,0)), SUM(up), 0 "
                             "FROM samples WHERE inb IS NOT NULL GROUP BY pid, (ts/?)", (res, res, res, res))
            s.db.commit()

    # ---------- SSH 監控的帳密（只存在這台電腦，不會送到網頁） ----------
    def ssh_creds(s, host):
        c = (s.settings.get("ssh") or {}).get(host)
        if not c: return None
        return {"user": c.get("user", ""), "password": unprotect(c.get("pw")), "hostkey": c.get("hostkey", "")}

    def add_ssh_device(s, info, user, password):
        """把 SSH 監控設備加到圖上（同 IP 的設備就沿用並補上介面）。回傳 (設備, 是否新建)。"""
        ip, port = info["host"], int(info.get("port") or 22); key = f"{ip}:{port}"
        s.settings.setdefault("ssh", {})[key] = {"user": user, "pw": protect(password), "hostkey": info.get("hostkey", "")}
        s.save_settings()
        with s.lock:
            proj = json.loads(json.dumps(s.project)); devs = proj.setdefault("devices", [])
        d = next((x for x in devs if x.get("ip") == ip or (x.get("sshmon") or {}).get("host") == key), None)
        created = d is None
        if created:
            typ = info.get("type") or "router"
            d = {"id": ns.nid("d"), "type": "end" if typ == "server" else typ, "name": info.get("name") or ip, "brand": info.get("brand", ""),
                 "model": info.get("model", ""), "ip": ip, "mac": "", "gw": "", "loc": "", "rack": "", "u": "", "uh": "", "x": 0, "y": 0, "ports": []}
            if typ == "server": d["kind"] = "伺服器"
            devs.append(d)
        d["sshmon"] = {"host": key}; d.pop("monitor", None)
        d["note"] = " ".join(x for x in [f"SSH 監控 {time.strftime('%Y-%m-%d')}", info.get("firmware", ""), info.get("kernel", "")] if x)
        if info.get("brand") and not d.get("brand"): d["brand"] = info["brand"]
        if info.get("model") and not d.get("model"): d["model"] = info["model"]
        bylab = {str(p.get("label", "")).lower(): p for p in d.get("ports", [])}
        for ifn, lab, note in info.get("ports", []):
            p = bylab.get(lab.lower()) or next((q for q in d["ports"] if q.get("ifName") == ifn), None)
            if not p:
                p = {"id": ns.nid("p"), "label": lab, "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": note}
                d["ports"].append(p)
            p["ifName"] = ifn
        others = [x for x in devs if x is not d and (x.get("x") or x.get("y"))]
        if created and others:   # 放在現有圖的右邊，不打亂原本的版面
            d["x"] = max(x.get("x") or 0 for x in others) + 300; d["y"] = min(x.get("y") or 0 for x in others)
        s.set_project(proj)
        return d, created

    def remove_ssh(s, dev_id):
        """停止這台設備的 SSH 監控並刪掉帳密（設備留在圖上）。"""
        with s.lock:
            proj = json.loads(json.dumps(s.project))
        d = next((x for x in proj.get("devices", []) if x["id"] == dev_id), None)
        if not d or not d.get("sshmon"): return False
        key = d.pop("sshmon")["host"]; d["monitor"] = False
        (s.settings.get("ssh") or {}).pop(key, None); s.save_settings()
        s.set_project(proj)
        return True

    def save_settings(s):
        with s.lock:
            tmp = os.path.join(s.root, "settings.json.tmp")
            json.dump(s.settings, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1); os.replace(tmp, os.path.join(s.root, "settings.json"))

    # ---------- 專案清單 ----------
    def projects(s):
        out = []
        with s.lock:
            for x in s.reg["list"]:
                cur = x["id"] == s.reg["current"]; n = None; rev = None
                if cur: n, rev = len(s.project.get("devices", [])), s.rev
                else:
                    try:
                        o = json.load(open(os.path.join(s._pdir(x["id"]), "project.json"), encoding="utf-8"))
                        n, rev = len((o.get("project") or {}).get("devices", [])), o.get("rev")
                    except Exception: n = 0
                out.append({"id": x["id"], "name": x.get("name") or x["id"], "created": x.get("created", 0), "devices": n, "rev": rev, "current": cur})
            return {"current": s.reg["current"], "list": out}

    def _clean_name(s, name, exclude=None):
        name = re.sub(r"\s+", " ", str(name or "")).strip()[:40]
        if not name: return None, "請輸入專案名稱"
        if any(x.get("name") == name and x["id"] != exclude for x in s.reg["list"]): return None, "已經有同名的專案"
        return name, None

    def project_new(s, name, copy_from=None):
        """新增專案（不切換）。copy_from 給專案 id 就複製它的圖（不含監控紀錄）。回傳 (id, 錯誤)。"""
        with s.lock:
            name, err = s._clean_name(name)
            if err: return None, err
            if len(s.reg["list"]) >= 50: return None, "專案太多了（上限 50 個）"
            src = None
            if copy_from:
                if not any(x["id"] == copy_from for x in s.reg["list"]): return None, "找不到要複製的專案"
                if copy_from == s.reg["current"]: src = s.project
                else:
                    try: src = (json.load(open(os.path.join(s._pdir(copy_from), "project.json"), encoding="utf-8")).get("project") or None)
                    except Exception: src = None
            pid = "p" + secrets.token_hex(4)
            d = s._pdir(pid); os.makedirs(d, exist_ok=True)
            proj = {k: (src or {}).get(k, []) for k in PROJECT_KEYS}
            json.dump({"rev": 1, "savedAt": time.strftime("%Y-%m-%dT%H:%M:%S"), "project": proj}, open(os.path.join(d, "project.json"), "w", encoding="utf-8"), ensure_ascii=False)
            s.reg["list"].append({"id": pid, "name": name, "created": int(time.time())}); s._save_reg()
            return pid, None

    def project_switch(s, pid):
        with s.lock:
            if not any(x["id"] == pid for x in s.reg["list"]): return False
            if pid == s.reg["current"]: return True
            s._open(pid); s._save_reg(); return True

    def project_rename(s, pid, name):
        with s.lock:
            x = next((x for x in s.reg["list"] if x["id"] == pid), None)
            if not x: return "找不到這個專案"
            name, err = s._clean_name(name, pid)
            if err: return err
            x["name"] = name; s._save_reg(); return None

    def project_delete(s, pid):
        with s.lock:
            if pid == "default": return "預設專案不能刪除（可以改名，或把裡面的設備清掉）"
            if pid == s.reg["current"]: return "目前開著的專案不能刪除，請先切換到別的專案"
            if not any(x["id"] == pid for x in s.reg["list"]): return "找不到這個專案"
            import shutil
            shutil.rmtree(s._pdir(pid), ignore_errors=True)
            s.reg["list"] = [x for x in s.reg["list"] if x["id"] != pid]; s._save_reg(); return None

    def snmp_opts(s):
        c = s.settings["snmp"]
        return ns.opts(version=c.get("version", "2c"), community=unprotect(c.get("community")) or "public", user=c.get("user") or None,
                       auth_proto=c.get("auth_proto") or "SHA", auth_key=unprotect(c.get("auth_key")) or None, priv_proto=c.get("priv_proto") or "AES",
                       priv_key=unprotect(c.get("priv_key")) or None, context=c.get("context") or "", port=int(c.get("port") or 161),
                       timeout=float(c.get("timeout") or 2), retries=int(c.get("retries") if c.get("retries") is not None else 1))

    def set_project(s, project, base_rev=None, who="", note=None):
        with s.lock:
            if base_rev is not None and int(base_rev) != s.rev: return False
            project = {k: project.get(k, []) for k in PROJECT_KEYS}
            before = s.project
            s.project = project; s.rev += 1
            tmp = os.path.join(s.dir, "project.json.tmp")
            json.dump({"rev": s.rev, "savedAt": time.strftime("%Y-%m-%dT%H:%M:%S"), "project": project}, open(tmp, "w", encoding="utf-8"), ensure_ascii=False)
            os.replace(tmp, os.path.join(s.dir, "project.json"))
            if s.rev % 20 == 0:  # 定期留一份備份
                bk = os.path.join(s.dir, "backup"); os.makedirs(bk, exist_ok=True)
                json.dump(project, open(os.path.join(bk, f"project-{time.strftime('%Y%m%d-%H%M%S')}.json"), "w", encoding="utf-8"), ensure_ascii=False)
            s._record_rev(before, project, who, note)
            return True

    # ---------- 歷史版本 ----------
    REV_MERGE_SECS = 120    # 同一個人連續修改（例如拖曳設備）合併成一筆
    REV_KEEP = 500

    def _add_rev(s, rev, project, who, summary, ts, detail=None):
        s.db.execute("INSERT OR REPLACE INTO revs VALUES (?,?,?,?,?,?)", (rev, ts, who or "", summary, json.dumps(detail or {}, ensure_ascii=False),
                                                                     zlib.compress(json.dumps(project, ensure_ascii=False).encode("utf-8"), 6)))

    def _record_rev(s, before, after, who, note):
        now = int(time.time())
        last = s.db.execute("SELECT rev, ts, who, detail FROM revs ORDER BY rev DESC LIMIT 1").fetchone()
        base = before
        if last and not note and last[2] == (who or "") and now - last[1] < s.REV_MERGE_SECS:
            prev = s.db.execute("SELECT data FROM revs WHERE rev < ? ORDER BY rev DESC LIMIT 1", (last[0],)).fetchone()
            base = json.loads(zlib.decompress(prev[0])) if prev else {}
            s.db.execute("DELETE FROM revs WHERE rev=?", (last[0],))
        detail = diff_projects(base or {}, after)
        s._add_rev(s.rev, after, who, note or detail["text"], now, detail)
        n = s.db.execute("SELECT COUNT(*) FROM revs").fetchone()[0]
        if n > s.REV_KEEP: s.db.execute("DELETE FROM revs WHERE rev IN (SELECT rev FROM revs ORDER BY rev LIMIT ?)", (n - s.REV_KEEP,))
        s.db.commit()

    def revs(s, limit=200):
        with s.lock:
            rows = s.db.execute("SELECT rev, ts, who, summary, detail FROM revs ORDER BY rev DESC LIMIT ?", (limit,)).fetchall()
        return [{"rev": r[0], "ts": r[1], "who": r[2], "summary": r[3], "detail": json.loads(r[4] or "{}"), "current": r[0] == s.rev} for r in rows]

    def rev_project(s, rev):
        with s.lock:
            r = s.db.execute("SELECT data, ts FROM revs WHERE rev=?", (int(rev),)).fetchone()
        return (json.loads(zlib.decompress(r[0])), r[1]) if r else (None, None)

    def restore(s, rev, who=""):
        proj, ts = s.rev_project(rev)
        if proj is None: return False
        return s.set_project(proj, None, who, f"還原到 #{rev}（{time.strftime('%m/%d %H:%M', time.localtime(ts))} 的版本）")

    # ---------- 事件 ----------
    def add_event(s, ev):
        text = na.event_line(ev)
        with s.lock:
            cur = s.db.execute("INSERT INTO events(ts, kind, level, dev, port, text, data) VALUES (?,?,?,?,?,?,?)",
                               (int(ev.get("ts") or time.time()), ev["kind"], na.LEVEL.get(ev["kind"], "info"), ev.get("dev") or "", ev.get("port") or "", text,
                                json.dumps(ev, ensure_ascii=False)))
            s.db.commit(); return cur.lastrowid

    def events(s, since_id=0, limit=200, dev=None):
        q, a = "SELECT id, ts, kind, level, dev, port, text FROM events WHERE id > ?", [int(since_id or 0)]
        if dev: q += " AND dev = ?"; a.append(dev)
        with s.lock:
            rows = s.db.execute(q + " ORDER BY id DESC LIMIT ?", a + [int(limit)]).fetchall()
        return [{"id": r[0], "ts": r[1], "kind": r[2], "level": r[3], "dev": r[4], "port": r[5], "text": r[6]} for r in rows]

    # ---------- 圖面比對 ----------
    def audit_save(s, findings, verified, info):
        """寫入這一輪比對結果；回傳新出現的問題。已略過（ignored）的維持略過，這輪沒再出現的標成已解決。"""
        now = int(time.time()); new = []
        with s.lock:
            cur = {r[0]: r[1] for r in s.db.execute("SELECT key, status FROM audit")}
            keys = set()
            for f in findings:
                keys.add(f["key"]); st = cur.get(f["key"])
                if st is None or st in ("resolved", "fixed"):
                    s.db.execute("INSERT OR REPLACE INTO audit VALUES (?,?,?,?,?,?,?,?,?,?,?)", (f["key"], f["kind"], f.get("level", "warn"), f.get("dev") or "", f.get("port") or "", f.get("cable") or "",
                                 f["text"], json.dumps(f.get("fix"), ensure_ascii=False), now, now, "open"))
                    new.append(f)
                else:
                    s.db.execute("UPDATE audit SET last=?, text=?, fix=?, cable=? WHERE key=?", (now, f["text"], json.dumps(f.get("fix"), ensure_ascii=False), f.get("cable") or "", f["key"]))
            for k, st in cur.items():
                if k not in keys and st in ("open", "fixed"): s.db.execute("UPDATE audit SET status='resolved', last=? WHERE key=?", (now, k))
            s.db.execute("DELETE FROM audit WHERE status='resolved' AND last < ?", (now - 30 * 86400,))
            s.db.executemany("INSERT OR REPLACE INTO verify VALUES (?,?,?)", [(c, now, how) for c, how in verified.items()])
            s.db.executemany("DELETE FROM verify WHERE cable=?", [(f["cable"],) for f in findings if f.get("cable")])
            s.settings["audit_last"] = dict(info, ts=now); s.save_settings()
            s.db.commit()
        return new

    def audit_list(s):
        with s.lock:
            rows = s.db.execute("SELECT key, kind, level, dev, port, cable, text, fix, first, last, status FROM audit WHERE status IN ('open','ignored','fixed') ORDER BY status, first DESC").fetchall()
            ver = {r[0]: [r[1], r[2]] for r in s.db.execute("SELECT cable, ts, how FROM verify")}
        return {"findings": [{"key": r[0], "kind": r[1], "level": r[2], "dev": r[3], "port": r[4], "cable": r[5], "text": r[6], "fix": json.loads(r[7] or "null"),
                              "first": r[8], "last": r[9], "status": r[10]} for r in rows],
                "verify": ver, "last": s.settings.get("audit_last") or {}, "hours": s.settings.get("audit_hours", 6)}

    def audit_mark(s, key, status):
        with s.lock:
            s.db.execute("UPDATE audit SET status=? WHERE key=?", (status, key)); s.db.commit()

    def audit_open(s):
        with s.lock: return s.db.execute("SELECT COUNT(*) FROM audit WHERE status='open'").fetchone()[0]

    def object_history(s, oid, limit=500):
        """某台設備或某條線在各版本的樣子（只回傳有變的版本），給網頁算出「改了什麼」。"""
        with s.lock:
            rows = s.db.execute("SELECT rev, ts, who, data FROM (SELECT rev, ts, who, data FROM revs ORDER BY rev DESC LIMIT ?) ORDER BY rev", (limit,)).fetchall()
        out, last = [], None
        for rev, ts, who, data in rows:
            pj = json.loads(zlib.decompress(data))
            snap = object_snapshot(pj, oid)
            sig = json.dumps(snap, ensure_ascii=False, sort_keys=True)
            if sig != last: out.append({"rev": rev, "ts": ts, "who": who, **snap}); last = sig
        return out

    # ---------- 網路上看過的設備（新加入／離線） ----------
    def seen_update(s, items, src):
        """items: [{mac, ip, name, wireless, via}]。回傳事件清單（新設備、IP 變更）。第一次收到資料時當作基準，不發「新設備」。"""
        now = int(time.time()); evs = []
        with s.lock:
            # 第一次從某個來源（某台路由器、某台 Switch）讀到的清單當作基準，不算「新加入」
            srcs = s.settings.setdefault("inv_sources", [])
            baseline = not s.db.execute("SELECT 1 FROM seen LIMIT 1").fetchone() or (src and src not in srcs)
            if src and src not in srcs: srcs.append(src); s.save_settings()
            for it in items:
                mac = norm_mac(it.get("mac"))
                if not mac: continue
                ip = it.get("ip") or ""; name = it.get("name") or ""
                r = s.db.execute("SELECT ip, name, first, gone, ips FROM seen WHERE mac=?", (mac,)).fetchone()
                if ip and not baseline:
                    other = s.db.execute("SELECT mac, name FROM seen WHERE ip=? AND mac<>? AND last > ?", (ip, mac, now - 1800)).fetchone()
                    k = (ip, *sorted([mac, other[0]])) if other else None
                    if other and now - s.conflicts.get(k, 0) > 6 * 3600:
                        s.conflicts[k] = now
                        evs.append({"kind": "ipconflict", "ip": ip, "name": ip, "mac": mac, "ts": now, "detail": f"{mac.upper()}（{name or ns.oui_vendor(mac.upper()) or '?'}）和 {other[0].upper()}（{other[1] or ns.oui_vendor(other[0].upper()) or '?'}）同時使用"})
                if not r:
                    vendor = ns.oui_vendor(mac.upper())
                    s.db.execute("INSERT INTO seen VALUES (?,?,?,?,?,?,?,?,?,0,?)", (mac, ip, name, vendor, 0 if baseline else now, now, src, it.get("via") or "", 1 if it.get("wireless") else 0, ip))
                    if not baseline: evs.append({"kind": "newdev", "mac": mac, "ip": ip, "name": name or vendor or mac, "ts": now, "detail": f"由 {src} 看到" if src else None})
                else:
                    ips = [x for x in (r[4] or "").split(",") if x]
                    if ip and ip not in ips: ips = (ips + [ip])[-5:]
                    if ip and r[0] and ip != r[0]: evs.append({"kind": "ipchange", "mac": mac, "ip": ip, "name": name or r[1] or mac, "ts": now, "detail": f"原本 {r[0]}"})
                    s.db.execute("UPDATE seen SET ip=COALESCE(NULLIF(?,''), ip), name=COALESCE(NULLIF(?,''), name), last=?, src=?, via=COALESCE(NULLIF(?,''), via), wireless=?, gone=0, ips=? WHERE mac=?",
                                 (ip, name, now, src, it.get("via") or "", 1 if it.get("wireless") else 0, ",".join(ips), mac))
                    if r[3]: evs.append({"kind": "back", "mac": mac, "ip": ip, "name": name or r[1] or mac, "ts": now})
            s.db.commit()
        return evs

    def seen_gone(s, hours, known_macs):
        """圖上的設備（有 MAC）超過 hours 小時沒出現：發一次「很久沒出現」。"""
        now = int(time.time()); evs = []
        with s.lock:
            for mac, ip, name, last in s.db.execute("SELECT mac, ip, name, last FROM seen WHERE gone=0 AND last < ?", (now - hours * 3600,)).fetchall():
                s.db.execute("UPDATE seen SET gone=1 WHERE mac=?", (mac,))
                if mac in known_macs: evs.append({"kind": "gone", "mac": mac, "ip": ip, "name": known_macs[mac] or name or mac, "ts": now, "detail": f"最後出現 {time.strftime('%m/%d %H:%M', time.localtime(last))}"})
            s.db.commit()
        return evs

    def seen_set_name(s, mac, name):
        with s.lock:
            s.db.execute("UPDATE seen SET name=? WHERE mac=? AND (name IS NULL OR name='')", (name, mac)); s.db.commit()

    def seen_list(s):
        with s.lock:
            rows = s.db.execute("SELECT mac, ip, name, vendor, first, last, src, via, wireless, gone, ips FROM seen ORDER BY last DESC").fetchall()
        return [{"mac": r[0], "ip": r[1], "name": r[2], "vendor": r[3], "first": r[4], "last": r[5], "src": r[6], "via": r[7], "wireless": bool(r[8]), "gone": bool(r[9]),
                 "ips": [x for x in (r[10] or "").split(",") if x]} for r in rows]

    def seen_forget(s, macs):
        with s.lock:
            s.db.executemany("DELETE FROM seen WHERE mac=?", [(norm_mac(m),) for m in macs]); s.db.commit()

    def add_samples(s, rows, speeds=None):
        if not rows: return
        speeds = speeds or {}
        agg = []
        for (t, pid, i, o, up, _ie, _oe) in rows:
            if i is None and o is None: continue
            for res, _ in ROLLUPS:
                agg.append((pid, res, t // res * res, i or 0, o or 0, i or 0, o or 0, up or 0, speeds.get(pid) or 0))
        with s.lock:
            s.db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?)", rows)
            s.db.executemany("INSERT INTO rollup VALUES (?,?,?,1,?,?,?,?,?,?) ON CONFLICT(pid, res, ts) DO UPDATE SET n=n+1, sin=sin+excluded.sin, sout=sout+excluded.sout, "
                             "xin=MAX(xin, excluded.xin), xout=MAX(xout, excluded.xout), upn=upn+excluded.upn, spd=MAX(spd, excluded.spd)", agg)
            s.db.commit()

    def mrtg(s, pid):
        """MRTG 的四張圖：每點 = [時間, 平均進, 平均出, 最大進, 最大出]。"""
        now = int(time.time()); out = {}; spd = 0
        with s.lock:
            for (res, keep), (name, span) in zip(ROLLUPS, MRTG_VIEWS):
                rows = s.db.execute("SELECT ts, sin/n, sout/n, xin, xout, spd FROM rollup WHERE pid=? AND res=? AND ts>=? ORDER BY ts", (pid, res, now - span)).fetchall()
                spd = max([spd] + [r[5] or 0 for r in rows])
                out[name] = {"res": res, "span": span, "points": [[r[0], r[1], r[2], r[3], r[4]] for r in rows]}
        return {"port": pid, "speed": spd, "now": now, "graphs": out}

    def mrtg_device(s, dev_id, view="day"):
        """一台設備所有埠的同一張圖（日／週／月／年）。"""
        views = dict(MRTG_VIEWS); res_of = {n: r for (r, _k), (n, _s) in zip(ROLLUPS, MRTG_VIEWS)}
        if view not in views: view = "day"
        d = next((x for x in s.project.get("devices", []) if x.get("id") == dev_id), None)
        if not d: return {"device": dev_id, "view": view, "ports": {}}
        now = int(time.time()); res = res_of[view]; pids = [p["id"] for p in d.get("ports", [])]; out = {}
        with s.lock:
            for pid in pids:
                rows = s.db.execute("SELECT ts, sin/n, sout/n, xin, xout, spd FROM rollup WHERE pid=? AND res=? AND ts>=? ORDER BY ts", (pid, res, now - views[view])).fetchall()
                if rows:
                    out[pid] = {"speed": max(r[5] or 0 for r in rows), "points": [[r[0], r[1], r[2], r[3], r[4]] for r in rows]}
        return {"device": dev_id, "view": view, "res": res, "span": views[view], "now": now, "ports": out}

    def mrtg_summary(s):
        """所有埠最近 24 小時：平均／最大，以及 30 分鐘一點的小圖。"""
        since = int(time.time()) - 86400; res = {}
        with s.lock:
            for pid, ts, ai, ao, mi, mo, sp in s.db.execute("SELECT pid, ts, sin/n, sout/n, xin, xout, spd FROM rollup WHERE res=1800 AND ts>=? ORDER BY pid, ts", (since,)):
                r = res.setdefault(pid, {"spark": [], "max_in": 0, "max_out": 0, "speed": 0, "_si": 0, "_so": 0})
                r["spark"].append([ts, round(ai or 0), round(ao or 0)])
                r["max_in"] = max(r["max_in"], ai or 0); r["max_out"] = max(r["max_out"], ao or 0); r["speed"] = max(r["speed"], sp or 0)
                r["_si"] += ai or 0; r["_so"] += ao or 0
        for r in res.values():
            n = max(1, len(r["spark"])); r["avg_in"] = r.pop("_si") / n; r["avg_out"] = r.pop("_so") / n
        return res

    def purge(s):
        with s.lock:
            now = int(time.time())
            s.db.execute("DELETE FROM events WHERE ts < ?", (now - 180 * 86400,))
            s.db.execute("DELETE FROM samples WHERE ts < ?", (now - int(s.settings.get("retention_days", 7)) * 86400,))
            for res, keep in ROLLUPS: s.db.execute("DELETE FROM rollup WHERE res=? AND ts < ?", (res, now - keep))
            s.db.commit()

    def history(s, pid, hours=24, points=360):
        since = int(time.time() - hours * 3600)
        with s.lock:
            rows = s.db.execute("SELECT ts, inb, outb, up, ierr, oerr FROM samples WHERE pid=? AND ts>=? ORDER BY ts", (pid, since)).fetchall()
        if len(rows) <= points: return [list(r) for r in rows]
        step = len(rows) / points; out = []
        for i in range(points):
            chunk = rows[int(i * step):int((i + 1) * step)] or [rows[-1]]
            out.append([chunk[-1][0], max(r[1] or 0 for r in chunk), max(r[2] or 0 for r in chunk), min(r[3] for r in chunk), sum(r[4] or 0 for r in chunk), sum(r[5] or 0 for r in chunk)])
        return out

# ───────────────────────── poller ─────────────────────────
OPER, HC_IN, HC_OUT, IN32, OUT32, IERR, OERR, HSPEED = ("1.3.6.1.2.1.2.2.1.8", "1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.31.1.1.1.10", "1.3.6.1.2.1.2.2.1.10",
                                                       "1.3.6.1.2.1.2.2.1.16", "1.3.6.1.2.1.2.2.1.14", "1.3.6.1.2.1.2.2.1.20", "1.3.6.1.2.1.31.1.1.1.15")
UPTIME = "1.3.6.1.2.1.1.3.0"
MONITOR_TYPES = {"fw", "router", "sw", "hub", "ap"}

def counter_delta(now, before, wrap):
    """計數器差值。變小時：接近上限才當作繞回，否則是設備重開機／計數歸零，這一次不算（避免流量圖出現假尖峰）。"""
    d = now - before
    if d >= 0: return d
    if wrap == 2 ** 32 and before > wrap * 0.75: return d + wrap
    return None


def too_fast(din, dout, dt_, speed):
    """超過介面速率 1.5 倍的值不可能是真的（計數器異常），丟掉這一點。"""
    return bool(speed) and max(din, dout) * 8 / dt_ > speed * 1.5


PASS_TYPES = {"patch", "seat"}
INFRA_TYPES = {"fw", "router", "sw", "hub", "ap"}

def far_ends(project):
    """每個埠沿著線（穿過配線架、資訊座）走到底的另一端設備：{埠id: 設備}。"""
    owner, port, cab = {}, {}, {}
    for d in project.get("devices", []):
        for p in d.get("ports", []): owner[p["id"]] = d; port[p["id"]] = p
    for c in project.get("cables", []): cab[c.get("a")] = c; cab[c.get("b")] = c
    out = {}
    for pid in cab:
        if pid not in owner: continue
        cur, seen = pid, {pid}
        for _ in range(64):
            c = cab.get(cur)
            if not c: break
            nx = c["b"] if c.get("a") == cur else c.get("a")
            if nx not in owner or nx in seen: break
            seen.add(nx); cur = nx
            d, p = owner[nx], port[nx]
            if d.get("type") in PASS_TYPES and p.get("pair") and p["pair"] not in seen:
                seen.add(p["pair"]); cur = p["pair"]; continue
            break
        if cur != pid and owner.get(cur) is not owner[pid]: out[pid] = owner[cur]
    return out, owner, port


PROBE_EVERY = 3600
PROBE_END_KINDS = {"伺服器", "NAS", "NVR 錄影主機", "印表機"}

def probe_candidates(project, self_set):
    """還沒有 SNMP 監控、但可能有 SNMP 的設備：網路設備，以及伺服器、NAS、NVR、印表機。"""
    out = []
    for d in project.get("devices", []):
        if d.get("demo"): continue
        ip = str(d.get("ip") or "").strip()
        if not ip or not re.match(r"^[\w.\-]+$", ip) or ip in self_set: continue
        if (d.get("snmp") or {}).get("host") or (d.get("sshmon") or {}).get("host") or d.get("snmp_probe") is False: continue
        net = d.get("type") in MONITOR_TYPES
        if net and d.get("monitor") is not False: continue            # 已經在輪詢清單裡
        if not net and not (d.get("type") == "end" and d.get("kind") in PROBE_END_KINDS): continue
        out.append(d)
    return out

def snmp_ports(cli):
    """讀實體介面：[(ifIndex, 標籤, 種類, 原始名稱)]。"""
    names = ns.by_index(cli.walk(ns.IF_NAME), ns.IF_NAME); descr = ns.by_index(cli.walk(ns.IF_DESCR), ns.IF_DESCR)
    types = ns.by_index(cli.walk(ns.IF_TYPE), ns.IF_TYPE); speeds = ns.by_index(cli.walk(ns.IF_HSPEED), ns.IF_HSPEED)
    out = []
    for i in sorted(set(names) | set(descr), key=lambda x: int(x) if str(x).isdigit() else 0):
        n = ns.s_(names.get(i)) or ns.s_(descr.get(i))
        it = {"name": n, "descr": ns.s_(descr.get(i)), "type": int(types.get(i) or 0), "speed": int(speeds.get(i) or 0) * 1_000_000}
        if n and ns.is_phys(it): out.append((i, ns.port_label(n), ns.port_kind(it), n))
    return out


class Poller:
    def __init__(s, store, log=print, emit=None):
        s.store, s.log = store, log
        s.emit = emit or (lambda ev: None)
        s.arp = {}           # host → 上次讀 ARP 表的時間
        s.inv_t = 0          # 上次整理「網路上的設備」的時間
        s.nb_tried = {}      # IP → 上次用 NetBIOS 問名稱的時間
        s.ptr_tried = {}     # IP → 上次用反向 DNS（PTR）問名稱的時間
        s.nb_busy = False
        s.probe_t = time.time() - PROBE_EVERY + 90   # 啟動 1～2 分鐘後先試一次 SNMP
        s.probe_force = False; s.probe_last = {"ts": 0, "tried": 0, "found": []}
        s.audit_t = time.time() - 3600 * 6 + 180   # 啟動 3 分鐘後先比對一次
        s.audit_force = False; s.audit_busy = False
        s.dns_t = time.time() - 3600 * 6 + 240; s.dns_force = False; s.dns_busy = False; s.dns_prog = {}   # 啟動 4 分鐘後先對帳一次
        try: s.dns_last = json.load(open(os.path.join(s.store.dir, "dnscheck.json"), encoding="utf-8"))
        except Exception: s.dns_last = {}
        s.status = {"ts": 0, "devices": {}, "ports": {}}
        s.prev = {}          # (host, ifIndex) → (t, in, out, ierr, oerr)
        s.ifmaps = {}        # host → (time, {label → ifIndex})
        s.links = {}         # "ip:port" → sm.SshLink（保持連線）
        s.clients = {}       # host → (時間, [用戶端])：路由器上的有線／無線設備，每 5 分鐘更新
        s.thread = None; s.stop_ev = threading.Event(); s.wake = threading.Event()
        s.running = False; s.last_cycle = 0; s.cycle_secs = 0

    def reset(s):
        """換專案：丟掉上一個專案的即時狀態（埠流量基準、探索進度…），重新開始。"""
        s.ptr_tried = {}; s.arp = {}; s.inv_t = 0; s.status = {"ts": 0, "devices": {}, "ports": {}}; s.prev = {}; s.ifmaps = {}; s.clients = {}
        s.probe_force = False; s.probe_t = time.time() - PROBE_EVERY + 90; s.probe_last = {"ts": 0, "tried": 0, "found": []}
        s.audit_t = time.time() - 3600 * 6 + 180; s.dns_t = time.time() - 3600 * 6 + 240; s.dns_prog = {}
        try: s.dns_last = json.load(open(os.path.join(s.store.dir, "dnscheck.json"), encoding="utf-8"))
        except Exception: s.dns_last = {}

    def targets(s):
        out = []
        for d in s.store.project.get("devices", []):
            if d.get("demo"): continue   # 範例（示範）設備：位址是假的，不去 SNMP／SSH
            if (d.get("sshmon") or {}).get("host"):
                out.append((d, "ssh://" + d["sshmon"]["host"])); continue
            # 跑 netmap.exe 的這台電腦：直接讀網卡，不需要 SNMP（網段探索建立的設備即使標成不監控也照樣讀）
            if not (d.get("snmp") or {}).get("host") and d.get("ip") and s.store.settings.get("monitor_self", True) and d["ip"] in self_ips():
                out.append((d, "local://" + d["ip"])); continue
            if d.get("monitor") is False: continue
            host = (d.get("snmp") or {}).get("host") or (d.get("ip") if d.get("type") in MONITOR_TYPES else "")
            host = (host or "").strip()
            if host and re.match(r"^[\w.\-]+(:\d+)?$", host): out.append((d, host))
        return out

    def ifmap(s, cli, host):
        cached = s.ifmaps.get(host)
        if cached and time.time() - cached[0] < 3600: return cached[1]
        names = ns.by_index(cli.walk(ns.IF_NAME), ns.IF_NAME); descr = ns.by_index(cli.walk(ns.IF_DESCR), ns.IF_DESCR)
        m = {}
        for i in set(names) | set(descr):
            for n in (ns.s_(names.get(i)), ns.s_(descr.get(i))):
                if not n: continue
                for k in (n, ns.short_if(n), ns.port_label(n)): m.setdefault(k.lower(), i)
        s.ifmaps[host] = (time.time(), m); return m

    def link(s, key):
        c = s.store.ssh_creds(key)
        if not c: raise sm.SshError("沒有這台設備的 SSH 帳密，請在 netmap.exe 重新加入")
        L = s.links.get(key)
        if not L or L.user != c["user"] or L.password != c["password"]:
            if L: L.close()
            ip, port = sm.split_host(key)
            L = s.links[key] = sm.SshLink(ip, port, c["user"], c["password"], c["hostkey"])
        return L

    def poll_local(s, d, host):
        ip = host[8:]; now = time.time(); res = {"dev": {"up": False, "err": "", "last": int(now), "via": "local"}, "ports": {}, "rows": []}
        nics = local_nics()
        if nics is None: res["dev"]["err"] = "讀不到這台電腦的網卡（缺少 psutil）"; return res
        nic = next((n for n, v in nics.items() if ip in v["ips"]), None)
        if not nic: res["dev"]["err"] = f"這台電腦目前沒有 {ip} 這個 IP"; return res
        v = nics[nic]; res["dev"]["up"] = True; t = time.time()
        wn = wifi_nics()
        if nic in wn or re.search(r"wi-?fi|wlan|wireless|無線", nic, re.I):
            w = wn.get(nic) or {}
            res["dev"]["link"] = {"wireless": True, "band": w.get("band", ""), "ssid": w.get("ssid", ""), "nic": nic, "src": "self"}
        else:
            res["dev"]["link"] = {"wireless": False, "nic": nic, "src": "self"}
        ports = d.get("ports", []); cabled = {x for c in s.store.project.get("cables", []) for x in (c.get("a"), c.get("b"))}
        p = next((q for q in ports if q.get("ifName") == nic), None) or next((q for q in ports if q["id"] in cabled), None) or (ports[0] if ports else None)
        if not p: return res
        k = (host, nic); prev = s.prev.get(k); s.prev[k] = (t, v["rx"], v["tx"], v["ie"], v["oe"])
        rin = rout = None; die = doe = 0
        if prev and t - prev[0] > 0.5:
            dt_ = t - prev[0]; din, dout = counter_delta(v["rx"], prev[1], 2 ** 64), counter_delta(v["tx"], prev[2], 2 ** 64)
            if din is not None and dout is not None and not too_fast(din, dout, dt_, v["speed"]):
                rin, rout = din * 8 / dt_, dout * 8 / dt_; die, doe = max(0, v["ie"] - prev[3]), max(0, v["oe"] - prev[4])
        res["ports"][p["id"]] = {"up": v["up"], "in": rin, "out": rout, "speed": v["speed"], "util": (max(rin or 0, rout or 0) / v["speed"]) if v["speed"] and rin is not None else None,
                                 "ie": die, "oe": doe, "if": nic}
        if rin is not None: res["rows"].append((int(t), p["id"], rin, rout, 1 if v["up"] is not False else 0, die, doe))
        return res

    def poll_ssh(s, d, host):
        key = host[6:]; now = time.time(); res = {"dev": {"up": False, "err": "", "last": int(now), "via": "ssh"}, "ports": {}, "rows": []}
        try:
            data = sm.read_ports(s.link(key))
        except Exception as e:
            res["dev"]["err"] = str(e) or "SSH 連線失敗"; return res
        res["dev"]["up"] = True; t = time.time()
        if d.get("type") in ("router", "ap", "fw") and d.get("clients") is not False:
            c = s.clients.get(host)
            if not c or time.time() - c[0] > 300:
                try: c = s.clients[host] = (time.time(), sm.read_clients(s.link(key), [(p.get("ifName"), p.get("label")) for p in d.get("ports", []) if p.get("ifName")]))
                except Exception: c = c or (time.time(), [])
            res["dev"]["clients"] = c[1]; res["dev"]["clients_at"] = int(c[0])
        for p in d.get("ports", []):
            ifn = p.get("ifName")
            if not ifn or ifn not in data: continue
            rx, tx, re_, te, up, speed = data[ifn]
            k = (host, ifn); prev = s.prev.get(k); s.prev[k] = (t, rx, tx, re_, te)
            rin = rout = None; die = doe = 0
            if prev and t - prev[0] > 0.5:
                dt_ = t - prev[0]; din, dout = rx - prev[1], tx - prev[2]
                din, dout = counter_delta(rx, prev[1], 2 ** 32), counter_delta(tx, prev[2], 2 ** 32)
                if din is not None and dout is not None and not too_fast(din, dout, dt_, speed):
                    rin, rout = din * 8 / dt_, dout * 8 / dt_
                    die, doe = max(0, re_ - prev[3]), max(0, te - prev[4])
            st = {"up": up, "in": rin, "out": rout, "speed": speed, "util": (max(rin or 0, rout or 0) / speed) if speed and rin is not None else None,
                  "ie": die, "oe": doe, "if": ifn}
            res["ports"][p["id"]] = st
            if rin is not None or up is not None:
                res["rows"].append((int(t), p["id"], rin, rout, 1 if up is not False else 0, die, doe))
        return res

    def poll_device(s, d, host, opts):
        now = time.time(); res = {"dev": {"up": False, "err": "", "last": int(now)}, "ports": {}, "rows": []}
        try:
            cli = ns.make_client(opts, host)
        except Exception as e:
            res["dev"]["err"] = str(e); return res
        try:
            try: up = cli.get([UPTIME, ns.SYS["name"]])
            except ns.SnmpError: up = None
            if not up: raise ns.SnmpError("no response")
            res["dev"]["up"] = True; res["dev"]["uptime"] = up.get(UPTIME)
            pidx = {}
            need_map = [p for p in d.get("ports", []) if p.get("ifIndex") in (None, "") and p.get("side") != 1]
            m = s.ifmap(cli, host) if need_map else {}
            for p in d.get("ports", []):
                if p.get("side") == 1: continue
                ix = p.get("ifIndex")
                if ix in (None, ""): ix = m.get(str(p.get("label", "")).lower())
                if ix not in (None, ""): pidx[p["id"]] = str(ix)
            ixs = sorted(set(pidx.values()), key=lambda x: int(x) if x.isdigit() else 0)
            vals = {}
            cols = [OPER, HC_IN, HC_OUT, IERR, OERR, HSPEED]
            oids = [f"{c}.{i}" for i in ixs for c in cols]
            for k in range(0, len(oids), 36): vals.update(cli.get(oids[k:k + 36]))
            missing = [i for i in ixs if f"{HC_IN}.{i}" not in vals]
            if missing:
                o2 = [f"{c}.{i}" for i in missing for c in (IN32, OUT32)]
                for k in range(0, len(o2), 36): vals.update(cli.get(o2[k:k + 36]))
            t = time.time(); cache = {}
            for i in ixs:
                inc = vals.get(f"{HC_IN}.{i}", vals.get(f"{IN32}.{i}")); outc = vals.get(f"{HC_OUT}.{i}", vals.get(f"{OUT32}.{i}"))
                ie, oe = vals.get(f"{IERR}.{i}", 0) or 0, vals.get(f"{OERR}.{i}", 0) or 0
                wrap = 2 ** 64 if f"{HC_IN}.{i}" in vals else 2 ** 32
                key = (host, i); prev = s.prev.get(key); s.prev[key] = (t, inc, outc, ie, oe)
                rin = rout = None; die = doe = 0
                if prev and inc is not None and prev[1] is not None and t - prev[0] > 0.5:
                    dt_ = t - prev[0]
                    din, dout = counter_delta(inc, prev[1], wrap), counter_delta(outc or 0, prev[2] or 0, wrap)
                    if din is not None and dout is not None and not too_fast(din, dout, dt_, (vals.get(f"{HSPEED}.{i}") or 0) * 1_000_000):
                        rin, rout = din * 8 / dt_, dout * 8 / dt_
                        die, doe = max(0, ie - prev[3]), max(0, oe - prev[4])
                speed = (vals.get(f"{HSPEED}.{i}") or 0) * 1_000_000
                oper = vals.get(f"{OPER}.{i}")
                cache[i] = {"up": None if oper is None else oper == 1, "in": rin, "out": rout, "speed": speed,
                            "util": (max(rin or 0, rout or 0) / speed) if speed and rin is not None else None, "ie": die, "oe": doe, "if": i}
            for pid, i in pidx.items():
                st = cache.get(i)
                if not st: continue
                res["ports"][pid] = st
                if st["in"] is not None or st["up"] is not None:
                    res["rows"].append((int(t), pid, st["in"], st["out"], 1 if st["up"] else 0, st["ie"], st["oe"]))
            # 路由器／防火牆／L3 Switch 的 ARP 表：每 10 分鐘讀一次，用來發現新加入、很久沒出現的設備
            if s.store.settings.get("inv_enabled", True) and d.get("type") in ("router", "fw", "sw") and time.time() - s.arp.get(host, 0) > 600:
                s.arp[host] = time.time()
                try:
                    arp = cli.walk(ns.ARP, max_rows=4000); items = []
                    for o, v in arp.items():
                        ipx = ".".join(o.split(".")[-4:]); mac = ns.mac_of(v)
                        if mac and not ipx.startswith(("224.", "239.", "255.")) and not ipx.endswith(".255"): items.append({"mac": mac, "ip": ipx})
                    res["inv"] = items
                except Exception:
                    pass
        except Exception as e:
            res["dev"]["err"] = "沒有回應" if "timeout" in str(e) or "no response" in str(e) else str(e)
        finally:
            try: cli.close()
            except Exception: pass
        return res

    def cycle(s):
        t0 = time.time(); opts = s.store.snmp_opts(); tg = s.targets()
        devs, ports, rows, inv = {}, {}, [], []
        if tg:
            with ThreadPoolExecutor(max_workers=min(16, len(tg))) as ex:
                for (d, host), r in zip(tg, ex.map(lambda x: s.poll_ssh(x[0], x[1]) if x[1].startswith("ssh://") else s.poll_local(x[0], x[1]) if x[1].startswith("local://") else s.poll_device(x[0], x[1], opts), tg)):
                    devs[d["id"]] = {**r["dev"], "host": host}; ports.update(r["ports"]); rows += r["rows"]
                    if r.get("inv"): inv.append((d.get("name") or host, r["inv"]))
                    if host.startswith("ssh://") and r["dev"].get("clients") and r["dev"].get("clients_at", 0) > s.arp.get(host, 0):
                        s.arp[host] = r["dev"]["clients_at"]
                        inv.append((d.get("name") or host, [{"mac": c["mac"], "ip": c["ip"], "name": c.get("name"), "wireless": bool(c.get("wireless")), "via": c.get("band") or c.get("iface")} for c in r["dev"]["clients"]]))
        s.store.add_samples(rows, {pid: p.get("speed") for pid, p in ports.items()})
        old = s.status
        s.status = {"ts": int(time.time()), "devices": devs, "ports": ports}
        try: s.transitions(old, s.status)
        except Exception as e: s.log(f"事件判斷錯誤：{e}")
        try: s.inventory(inv)
        except Exception as e: s.log(f"設備清單錯誤：{e}")
        hrs = float(s.store.settings.get("audit_hours", 6) or 0)
        if s.audit_force or (hrs > 0 and time.time() - s.audit_t > hrs * 3600):
            s.audit_force = False; s.audit_t = time.time()
            threading.Thread(target=s.run_audit, args=(opts,), daemon=True, name="audit").start()
        dh = float(s.store.settings.get("dns_hours", 6) or 0)
        if s.dns_force or (dh > 0 and time.time() - s.dns_t > dh * 3600):
            s.dns_force = False; s.dns_t = time.time()
            threading.Thread(target=s.run_dns, daemon=True, name="dnscheck").start()
        if s.store.settings.get("snmp_autoprobe", True) and (s.probe_force or time.time() - s.probe_t > PROBE_EVERY):
            s.probe_force = False; s.probe_t = time.time()
            try: s.autoprobe(opts)
            except Exception as e: s.log(f"自動偵測 SNMP 錯誤：{e}")
        s.last_cycle = time.time(); s.cycle_secs = round(time.time() - t0, 2)
        down = [d for d in devs.values() if not d["up"]]
        s.log(f"輪詢完成：{len(devs)} 台設備（{len(down)} 台沒回應）、{len(ports)} 個埠，{s.cycle_secs} 秒")
        if int(t0) % 3600 < max(60, int(s.store.settings.get("interval", 60))): s.store.purge()

    def transitions(s, old, new):
        """和上一輪比：SNMP／SSH 設備沒回應、恢復；接到網路設備的埠（主幹）離線、恢復。"""
        if not old.get("ts"): return
        proj = s.store.project; byid = {d["id"]: d for d in proj.get("devices", [])}
        far, owner, port = far_ends(proj)
        for did, st in new["devices"].items():
            o = old["devices"].get(did)
            if not o or o.get("up") == st.get("up") or st.get("via") == "local": continue
            d = byid.get(did) or {}
            s.emit({"kind": "snmp_up" if st.get("up") else "snmp_down", "dev": did, "name": d.get("name", ""), "ip": d.get("ip", ""), "ts": new["ts"],
                    "detail": None if st.get("up") else (st.get("err") or "沒有回應")})
        for pid, st in new["ports"].items():
            o = old["ports"].get(pid)
            if not o or o.get("up") is None or st.get("up") is None or o["up"] == st["up"]: continue
            p, d, fd = port.get(pid) or {}, owner.get(pid) or {}, far.get(pid)
            if p.get("alert") in (False, "off"): continue
            if not (p.get("alert") in (True, "on") or (fd and fd.get("type") in INFRA_TYPES) or (fd and fd.get("type") == "end" and fd.get("kind") in ("伺服器", "NAS", "NVR 錄影主機", "ISP 數據機"))): continue
            s.emit({"kind": "port_up" if st["up"] else "port_down", "dev": d.get("id"), "port": pid, "name": d.get("name", ""), "port_name": f"埠 {p.get('label', '')}" + (f" → {fd.get('name')}" if fd else ""), "ts": new["ts"]})

    def inventory(s, inv):
        st = s.store.settings
        if not st.get("inv_enabled", True): return
        now = time.time()
        if now - s.inv_t > 600:   # 這台電腦自己的 ARP 表
            s.inv_t = now
            try:
                me = ns.arp_table()
                if me: inv.append(("netmap 主機", [{"mac": m, "ip": ip} for ip, m in me.items()]))
            except Exception: pass
            known = {norm_mac(d.get("mac")): d.get("name", "") for d in s.store.project.get("devices", []) if norm_mac(d.get("mac"))}
            for ev in s.store.seen_gone(int(st.get("inv_gone_hours") or 24), known): s.emit(ev)
            fill = True
        else: fill = False
        for src, items in inv:
            for ev in s.store.seen_update(items, src): s.emit(ev)
        if fill and not s.nb_busy:
            s.nb_busy = True
            threading.Thread(target=s.name_fill, daemon=True, name="nbnames").start()

    def ptr_lookup(s, ip, port=53):
        """反向 DNS（PTR）查名稱：先問設定的／這台電腦用的 DNS 伺服器（最多 3 台）。DHCP 發的 IP 通常會被 DHCP 伺服器或電腦自己登記進 DNS，
        手機和 IoT 不回應 NetBIOS 時，靠這個補名字。回傳主機名稱（不含網域尾碼），查不到回空字串。"""
        server, _dom, servers, _d = s.dns_target()
        for sv in list(dict.fromkeys(([server] if server else []) + servers))[:3]:
            stt, vals = ndc.dns_query(ndc.ptr_name(ip), sv, 12, timeout=1.2, port=port)
            if stt == "ok" and vals:
                n = vals[0].rstrip(".").split(".")[0]
                if n and not re.fullmatch(r"[\d\-]+", n) and n.lower() not in ("localhost",): return n
            if stt == "nx": return ""
        return ""

    def name_fill(s):
        """「網路上的設備」裡有 IP 沒名稱的：先用 NetBIOS 問電腦名稱，還是沒有的再用反向 DNS（PTR）查（每個 IP 各 6 小時最多問一次）"""
        try:
            now = time.time()
            todo = [it for it in s.store.seen_list() if it["ip"] and not it["name"] and not it["gone"] and now - (it["last"] or 0) < 3600
                    and now - s.nb_tried.get(it["ip"], 0) > 6 * 3600][:160]
            for it in todo: s.nb_tried[it["ip"]] = now
            if todo:
                with ThreadPoolExecutor(24) as ex:
                    res = list(ex.map(lambda it: (it, ndc.nbstat(it["ip"], timeout=1.0, tries=1)), todo))
                for it, r in res:
                    if r and r.get("name") and (not r.get("mac") or norm_mac(r["mac"]) == it["mac"]):
                        s.store.seen_set_name(it["mac"], r["name"])
        except Exception as e:
            s.log(f"NetBIOS 查名稱失敗：{e}")
        try:
            now = time.time()
            todo = [it for it in s.store.seen_list() if it["ip"] and not it["name"] and not it["gone"] and now - (it["last"] or 0) < 3600
                    and now - s.ptr_tried.get(it["ip"], 0) > 6 * 3600][:200]
            for it in todo: s.ptr_tried[it["ip"]] = now
            if todo:
                with ThreadPoolExecutor(16) as ex:
                    res = list(ex.map(lambda it: (it, s.ptr_lookup(it["ip"])), todo))
                n = 0
                for it, name in res:
                    if name: s.store.seen_set_name(it["mac"], name); n += 1
                if n: s.log(f"反向 DNS 補上 {n} 台設備的名稱")
        except Exception as e:
            s.log(f"反向 DNS 查名稱失敗：{e}")
        finally:
            s.nb_busy = False

    def ip_macs(s):
        """IP → MAC（「網路上的設備」最近一小時看到的）：NetBIOS 回應裡沒有 MAC 時用來補"""
        now = time.time(); m = {}
        for it in sorted(s.store.seen_list(), key=lambda x: x["last"] or 0):
            if it["ip"] and not it["gone"] and now - (it["last"] or 0) < 3600: m[it["ip"]] = it["mac"]
        return m

    def dns_rows_with_mac(s):
        rows = [dict(r) for r in ((s.dns_last or {}).get("rows") or [])]
        if any(not r.get("mac") for r in rows):
            m = s.ip_macs()
            for r in rows:
                if not r.get("mac") and r.get("ip") in m and r.get("status") not in ("ghost",): r["mac"] = m[r["ip"]]; r["mac_src"] = "arp"
        return rows

    def names_map(s):
        """MAC → {ip, name, src}：給網頁把只有 MAC／IP 的設備自動換成電腦名稱"""
        out = {}
        for it in s.store.seen_list():
            if it["gone"]: continue
            out[it["mac"]] = {"ip": it["ip"], "name": it["name"], "src": "seen", "vendor": it["vendor"]}
        for r in s.dns_rows_with_mac():
            m = norm_mac(r.get("mac"))
            if not m or not r.get("name") or r.get("status") in ("ghost", "nonb"): continue
            o = out.setdefault(m, {"ip": r["ip"], "name": "", "src": "netbios", "vendor": ns.oui_vendor(m.upper())})
            if not o["name"]: o["name"] = r["name"]; o["src"] = "netbios"
            if not o["ip"]: o["ip"] = r["ip"]
        return out

    def run_audit(s, opts):
        """圖面比對：讀每台有 SNMP 的網路設備的 LLDP／CDP 與 MAC 表，和圖上的線比對。"""
        if s.audit_busy: return
        s.audit_busy = True
        try:
            proj = s.store.project
            devs = [d for d in proj.get("devices", []) if (d.get("snmp") or {}).get("host") and d.get("type") in INFRA_TYPES and d.get("monitor") is not False]
            coll, fails = {}, []
            def one(d):
                h = d["snmp"]["host"]
                try: return d, ns.collect(ns.make_client(opts, h), h, want_fdb=True, log=lambda *a: None)
                except Exception as e: return d, e
            if devs:
                with ThreadPoolExecutor(max_workers=min(8, len(devs))) as ex:
                    for d, r in ex.map(one, devs):
                        if isinstance(r, Exception): fails.append(d.get("name", ""))
                        else: coll[d["id"]] = r
            findings, verified = nau.audit(proj, coll)
            new = s.store.audit_save(findings, verified, {"devices": len(devs), "ok": len(coll), "fail": fails, "findings": len(findings), "verified": len(verified)})
            s.log(f"圖面比對：讀了 {len(coll)}／{len(devs)} 台，{len(findings)} 個差異（新的 {len(new)} 個），確認 {len(verified)} 條線")
            for f in new:
                s.emit({"kind": "drift", "dev": f.get("dev"), "port": f.get("port"), "name": "圖面比對", "detail": f["text"], "ts": int(time.time())})
        except Exception as e:
            s.log(f"圖面比對錯誤：{e}")
        finally:
            s.audit_busy = False

    def dns_target(s):
        """要用哪台 DNS 伺服器、哪個網域尾碼：設定優先，沒設就用這台電腦自己的 DNS 設定。"""
        st = s.store.settings; servers, dom = ndc.local_dns()
        server = (st.get("dns_server") or "").strip() or (servers[0] if servers else "")
        return server, (st.get("dns_domain") or "").strip().strip(".") or dom, servers, dom

    def run_dns(s):
        """DNS 對帳：NetBIOS 問出每個 IP 上的電腦名稱，和 AD DNS 的 A／PTR 記錄比對。"""
        if s.dns_busy: return
        server, domain, _a, _b = s.dns_target()
        if not server:
            s.dns_last = {"ts": int(time.time()), "error": "找不到 DNS 伺服器，請在設定填 AD 的 DNS 伺服器 IP", "rows": [], "summary": {}}; return
        s.dns_busy = True
        try:
            proj = s.store.project; ips, names = [], []
            priv = private_ip
            for d in proj.get("devices", []):
                if d.get("demo"): continue
                ip = str(d.get("ip") or "").split("/")[0]
                if priv(ip) and d.get("type") not in ("patch", "jack", "odf"): ips.append(ip)
                if d.get("name") and ndc.HOST_RE.match(d["name"]): names.append(d["name"])
            now = time.time()
            for r in s.store.seen_list():
                if not r["gone"] and now - (r["last"] or 0) < 86400 and priv(r["ip"]): ips.append(r["ip"])
                if r.get("name") and ndc.HOST_RE.match(r["name"]): names.append(r["name"])
            for dv in (s.status.get("devices") or {}).values():
                for c in dv.get("clients") or []:
                    if c.get("online") is not False and priv(c.get("ip")): ips.append(c["ip"])
                    if c.get("name") and ndc.HOST_RE.match(c["name"]): names.append(c["name"])
            ips = [ip for ip in dict.fromkeys(ips) if ip not in self_ips()][:1024] + [ip for ip in self_ips() if priv(ip)][:1]
            s.dns_prog = {"done": 0, "total": len(ips), "rows": [], "started": int(time.time())}
            def prog(k, n, row):
                s.dns_prog["done"] = k
                if row: s.dns_prog["rows"].append(row)
            r = ndc.check(ips, server, domain, names, log=s.log, progress=prog)
            r.update(ts=int(time.time()), server=server, domain=domain, checked=len(ips))
            old = {(x["status"], x["name"], x["ip"]) for x in (s.dns_last.get("rows") or []) if x.get("level") == "bad"}
            s.dns_last = r
            try: json.dump(r, open(os.path.join(s.store.dir, "dnscheck.json"), "w", encoding="utf-8"), ensure_ascii=False)
            except OSError: pass
            if r.get("error"): s.log("DNS 對帳：" + r["error"]); return
            new = [x for x in r["rows"] if x["level"] == "bad" and (x["status"], x["name"], x["ip"]) not in old]
            s.log(f"DNS 對帳：{r['summary'].get('hosts', 0)} 台電腦，{r['summary'].get('bad', 0)} 個問題（新的 {len(new)} 個）")
            for x in new[:20]:
                s.emit({"kind": "dns", "name": x["name"] or x["ip"], "ip": x["ip"], "detail": x["text"], "ts": int(time.time())})
        except Exception as e:
            s.log(f"DNS 對帳錯誤：{e}")
        finally:
            s.dns_busy = False

    def autoprobe(s, opts):
        """用已設定的 SNMP 帳密試圖上還沒監控的設備；有回應就開始監控，並用設備回報的介面補上埠號。"""
        cands = probe_candidates(s.store.project, self_ips())
        s.probe_last = {"ts": int(time.time()), "tried": len(cands), "found": []}
        if not cands: return
        def try_one(d):
            cli = None
            try:
                cli = ns.make_client(opts, d["ip"].strip(), quick=True)
                r = cli.get([ns.SYS["name"], ns.SYS["descr"]])
                if not r: return None
                ports = []
                try: ports = snmp_ports(cli)
                except Exception: pass
                return {"name": ns.s_(r.get(ns.SYS["name"])), "descr": ns.s_(r.get(ns.SYS["descr"])), "ports": ports}
            except Exception:
                return None
            finally:
                try: cli and cli.close()
                except Exception: pass
        with ThreadPoolExecutor(max_workers=min(16, len(cands))) as ex:
            res = dict(zip([d["id"] for d in cands], ex.map(try_one, cands)))
        hits = {k: v for k, v in res.items() if v}
        if not hits: return
        with s.store.lock: proj = json.loads(json.dumps(s.store.project))
        cabled = {x for c in proj.get("cables", []) for x in (c.get("a"), c.get("b"))}
        found = []
        for d in proj.get("devices", []):
            h = hits.get(d["id"])
            if not h: continue
            d["snmp"] = {"host": d["ip"].strip()}; d.pop("monitor", None)
            ports = d.setdefault("ports", []); added = mapped = 0
            if h["ports"]:
                by = {}
                for p in ports:
                    for k in (str(p.get("label", "")).lower(), str(p.get("ifName", "")).lower()): by.setdefault(k, p)
                used = set()
                for ix, lab, kind, raw in h["ports"]:
                    p = by.get(lab.lower()) or by.get(raw.lower()) or by.get(ns.short_if(raw).lower())
                    if p and p["id"] not in used: p["ifIndex"] = ix; used.add(p["id"]); mapped += 1; continue
                    ports.append({"id": ns.nid("p"), "label": lab, "kind": kind, "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": raw if raw != lab else "", "ifIndex": ix}); added += 1
                # 網段探索建立的「WAN／ETH1」這類佔位埠：沒接線又對不上就拿掉
                ports[:] = [p for p in ports if p.get("ifIndex") not in (None, "") or p["id"] in cabled or p.get("side") is not None]
            if h["descr"] and not d.get("model"):
                br = ns.brand_of({"sysDescr": h["descr"]})
                if br and not d.get("brand"): d["brand"] = br
            nm = h["name"] if re.match(r"^(\d+\.){3}\d+$", h["name"] or "") else (h["name"] or "").split(".")[0]
            if nm and re.match(r"^(\d+\.){3}\d+$|^(路由器|AP|Switch|設備)\b", d.get("name", "")): d["name"] = nm[:40]
            unm = [p for p in ports if p["id"] in cabled and p.get("ifIndex") in (None, "")]
            found.append({"dev": d["id"], "name": d.get("name"), "ip": d["ip"], "ports": len(h["ports"]), "added": added, "mapped": mapped, "unmapped": len(unm)})
        s.store.set_project(proj, None, "自動偵測 SNMP", f"自動偵測到 SNMP：{'、'.join(f['name'] for f in found)}")
        s.ifmaps.clear(); s.probe_last["found"] = found
        for f in found:
            s.emit({"kind": "snmp_found", "dev": f["dev"], "name": f["name"], "ip": f["ip"], "ts": int(time.time()),
                    "detail": f"讀到 {f['ports']} 個埠" + (f"，新增 {f['added']} 個" if f["added"] else "") + (f"；有 {f['unmapped']} 個已接線的埠對不上，請在設備屬性改成設備上的埠名稱，或重新掃描" if f["unmapped"] else "")})
        s.wake.set()

    def run(s):
        s.running = True
        while not s.stop_ev.is_set():
            try: s.cycle()
            except Exception as e: s.log(f"輪詢錯誤：{e}")
            s.wake.wait(max(10, int(s.store.settings.get("interval", 60)))); s.wake.clear()
        s.running = False

    def start(s):
        if s.thread and s.thread.is_alive(): return
        s.stop_ev.clear(); s.thread = threading.Thread(target=s.run, daemon=True, name="poller"); s.thread.start()

    def stop(s):
        s.stop_ev.set(); s.wake.set()
        for L in list(s.links.values()): L.close()
        s.links.clear()

    def poke(s):
        s.ifmaps.clear(); s.wake.set()

# ───────────────────────── 權限 ─────────────────────────
def hash_pw(pw, salt=None, it=200_000):
    salt = salt or secrets.token_hex(16)
    return f"pbkdf2${it}${salt}${hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes.fromhex(salt), it).hex()}"

def check_pw(pw, stored):
    try:
        _k, it, salt, h = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), int(it)).hex(), h)
    except Exception:
        return False

class Auth:
    """管理員登入的 session（只存在記憶體，服務重開要重新登入）與登入失敗限制。"""
    TTL = 12 * 3600
    def __init__(s): s.sessions = {}; s.fails = {}; s.lock = threading.Lock()
    def new(s):
        t = secrets.token_urlsafe(24)
        with s.lock: s.sessions[t] = time.time() + s.TTL
        return t
    def valid(s, t):
        if not t: return False
        with s.lock:
            exp = s.sessions.get(t)
            if not exp or exp < time.time(): s.sessions.pop(t, None); return False
            s.sessions[t] = time.time() + s.TTL; return True
    def drop(s, t=None):
        with s.lock:
            if t: s.sessions.pop(t, None)
            else: s.sessions.clear()
    def blocked(s, ip):
        with s.lock:
            f = [t for t in s.fails.get(ip, []) if t > time.time() - 600]; s.fails[ip] = f
            return len(f) >= 5
    def failed(s, ip):
        with s.lock: s.fails.setdefault(ip, []).append(time.time())

LOGIN_HTML = """<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RackTrace 登入</title><style>
:root{--bg:#F4F6F9;--card:#fff;--ink:#16202B;--mute:#5B6878;--line:#D9DFE7;--acc:#2563EB}
@media (prefers-color-scheme:dark){:root{--bg:#0F141B;--card:#18202A;--ink:#E6EBF1;--mute:#9AA7B6;--line:#2A3441;--acc:#4F8BFF}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft JhengHei",sans-serif}
form{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px 26px;width:min(360px,calc(100vw - 32px));box-sizing:border-box}
h1{font-size:19px;margin:0 0 6px}p{color:var(--mute);margin:0 0 18px;font-size:13.5px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:transparent;color:inherit;font:inherit}
button{margin-top:12px;width:100%;padding:10px;border:0;border-radius:9px;background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer}
.err{color:#D9443A;font-size:13px;min-height:20px;margin-top:8px}</style></head><body>
<form id="f"><h1>RackTrace</h1><p>這個監控服務需要登入才能查看。沒有密碼的話，請向管理員要一個「檢視連結」。</p>
<input type="password" id="pw" placeholder="管理密碼" autocomplete="current-password" autofocus aria-label="管理密碼"><button>登入</button><div class="err" id="e"></div></form>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Netmap':'1'},body:JSON.stringify({password:document.getElementById('pw').value})});
if(r.ok)location.replace('/'+location.hash);else{const j=await r.json().catch(()=>({}));document.getElementById('e').textContent=j.error||'密碼不對'}}</script></body></html>"""


# ───────────────────────── HTTP ─────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"netmap/{VERSION}"
    def log_message(s, fmt, *a): pass

    def _local(s):
        ip = s.client_address[0]
        return ip.startswith("127.") or ip == "::1" or ip in local_ips()

    def _send(s, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)): body = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        elif isinstance(body, str): body = body.encode("utf-8")
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            for vv in (v if isinstance(v, list) else [v]): s.send_header(k, vv)
        s.send_header("Cache-Control", "no-store"); s.send_header("X-Content-Type-Options", "nosniff"); s.end_headers(); s.wfile.write(body)

    def _cookie(s, name):
        for part in (s.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name: return urllib.parse.unquote(v)
        return ""

    def _detect_origin(s):
        """允許線上版偵測時，回傳可以放行的 Origin；否則 None。"""
        o = s.headers.get("Origin") or ""
        if s.server.store.settings.get("web_detect") and o in DETECT_ORIGINS and s._local(): return o
        return None

    # 權限：服務主機本身永遠是管理員；其他電腦要登入。沒設密碼時沿用「允許內網其他電腦編輯」。
    def is_admin(s): return s._local() or s.server.auth.valid(s._cookie("nm_a"))
    def can_edit(s):
        st = s.server.store.settings
        return s.is_admin() or (bool(st.get("lan_edit")) and not st.get("admin_hash"))
    def view_ok(s, token=None):
        st = s.server.store.settings
        if s.is_admin() or not st.get("view_required"): return True
        t = token or s._cookie("nm_v")
        return bool(t and st.get("view_token") and hmac.compare_digest(t, st["view_token"]))
    def who(s):
        name = urllib.parse.unquote(s.headers.get("X-Netmap-User") or "")[:40].strip()
        place = "服務主機" if s._local() else s.client_address[0]
        return f"{name}（{place}）" if name else place

    def body_json(s, limit=50 * 1024 * 1024):
        n = int(s.headers.get("Content-Length") or 0)
        if n > limit: raise ValueError("too large")
        return json.loads(s.rfile.read(n).decode("utf-8") or "{}") if n else {}

    def do_OPTIONS(s):
        o = s._detect_origin()
        if not o or urllib.parse.urlparse(s.path).path != "/api/ping": return s._send(403, {"error": "forbidden"})
        s._send(204, b"", "text/plain", {"Access-Control-Allow-Origin": o, "Vary": "Origin", "Access-Control-Allow-Methods": "GET",
                                          "Access-Control-Allow-Private-Network": "true", "Access-Control-Max-Age": "600"})

    def do_GET(s):
        st, po, sv = s.server.store, s.server.poller, getattr(s.server, "service", None)
        u = urllib.parse.urlparse(s.path); q = urllib.parse.parse_qs(u.query)
        arg = lambda k, d="": (q.get(k) or [d])[0]
        if u.path == "/api/ping":
            o = s._detect_origin()
            if o: return s._send(200, {"ok": True, "version": VERSION, "port": st.settings.get("port"), "detect": True},
                                 extra={"Access-Control-Allow-Origin": o, "Vary": "Origin", "Access-Control-Allow-Private-Network": "true"})
            return s._send(200, {"ok": True, "version": VERSION})
        if u.path in ("/", "/index.html"):
            tok = arg("t")
            if tok:   # 檢視連結：記在 cookie 裡，網址列不留 token
                if s.view_ok(tok):
                    return s._send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": f"nm_v={urllib.parse.quote(tok)}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"})
                return s._send(403, LOGIN_HTML.replace("請向管理員要一個「檢視連結」。", "這個檢視連結已經失效，請向管理員要新的連結。"), "text/html; charset=utf-8")
            if not s.view_ok(): return s._send(401, LOGIN_HTML, "text/html; charset=utf-8")
            html = web_override()
            if html is None:
                p = web_index()
                if not p: return s._send(500, "找不到網頁檔（web/index.html）", "text/plain; charset=utf-8")
                html = open(p, encoding="utf-8").read()
            with st.lock: boot = {"rev": st.rev, "pid": st.pid, "pname": next((x.get("name") for x in st.reg["list"] if x["id"] == st.pid), ""), "project": st.project, "interval": st.settings.get("interval", 60), "edit": s.can_edit(), "version": VERSION, "host": socket.gethostname(),
                                      "self_ips": sorted(self_ips()) if st.settings.get("monitor_self", True) else [],
                                      "admin": s.is_admin(), "local": s._local(), "auth": bool(st.settings.get("admin_hash")), "login": s.server.auth.valid(s._cookie("nm_a"))}
            inj = "<script>window.NETMAP_SERVER=" + json.dumps(boot, ensure_ascii=False).replace("</", "<\\/") + ";</script>"
            html = html.replace("</head>", inj + "\n</head>", 1)
            return s._send(200, html, "text/html; charset=utf-8")
        if not u.path.startswith("/api/"): return s._send(404, {"error": "not found"})
        if not s.view_ok(): return s._send(401, {"error": "需要登入或檢視連結"})
        if u.path == "/api/project":
            with st.lock: return s._send(200, {"rev": st.rev, "pid": st.pid, "project": st.project})
        if u.path == "/api/projects": return s._send(200, st.projects())
        if u.path == "/api/status":
            stat = po.status
            last_ev = st.events(0, 1)
            return s._send(200, {"rev": st.rev, "pid": st.pid, "ts": stat.get("ts", 0), "interval": st.settings.get("interval", 60), "running": po.running,
                                 "devices": stat.get("devices", {}), "ports": stat.get("ports", {}), "edit": s.can_edit(), "admin": s.is_admin(),
                                 "ping": sv.pinger.snapshot() if sv else {}, "ping_on": bool(st.settings.get("ping_enabled", True)),
                                 "ev": last_ev[0]["id"] if last_ev else 0, "audit_open": st.audit_open(),
                                 "dns_bad": ((po.dns_last or {}).get("summary") or {}).get("bad", 0), "dns_ts": (po.dns_last or {}).get("ts", 0)})
        if u.path == "/api/dnscheck":
            server, domain, servers, dom = po.dns_target()
            o = dict(po.dns_last or {}); o["rows"] = po.dns_rows_with_mac(); o.update(busy=po.dns_busy or po.dns_force, prog=po.dns_prog if (po.dns_busy or po.dns_force) else None, hours=st.settings.get("dns_hours", 6), cfg_server=st.settings.get("dns_server", ""),
                                                 cfg_domain=st.settings.get("dns_domain", ""), auto_servers=servers, auto_domain=dom, use_server=server, use_domain=domain)
            return s._send(200, o)
        if u.path == "/api/pinghist":
            snap = sv.pinger.snapshot(hist=True) if sv else {}
            return s._send(200, snap.get(arg("id")) or {})
        if u.path == "/api/events":
            return s._send(200, {"events": st.events(arg("since", "0"), min(1000, int(arg("limit", "200") or 200)), arg("dev") or None)})
        if u.path == "/api/revs":
            return s._send(200, {"rev": st.rev, "revs": st.revs(min(500, int(arg("limit", "200") or 200)))})
        if u.path == "/api/revs/get":
            proj, ts = st.rev_project(arg("rev", "0") or 0)
            return s._send(200, {"rev": int(arg("rev", "0") or 0), "ts": ts, "project": proj}) if proj is not None else s._send(404, {"error": "找不到這個版本"})
        if u.path == "/api/audit":
            o = st.audit_list(); o["busy"] = po.audit_busy; o["next"] = int(po.audit_t + float(st.settings.get("audit_hours", 6) or 0) * 3600) if st.settings.get("audit_hours", 6) else 0
            return s._send(200, o)
        if u.path == "/api/revs/object":
            return s._send(200, {"items": st.object_history(arg("id"))})
        if u.path == "/api/names":
            return s._send(200, {"macs": po.names_map() if po else {}})
        if u.path == "/api/seen":
            return s._send(200, {"items": st.seen_list(), "enabled": bool(st.settings.get("inv_enabled", True)), "gone_hours": st.settings.get("inv_gone_hours", 24)})
        if u.path in ("/api/scan/status", "/api/scan/defaults"):
            if not s._local() or not s.is_admin(): return s._send(403, {"error": "掃描只能在服務主機上操作"})
            if not sv: return s._send(500, {"error": "no service"})
            return s._send(200, sv.scan_status(int(arg("since", "0") or 0)) if u.path.endswith("status") else sv.scan_defaults())
        if u.path == "/api/settings":
            if not s.is_admin(): return s._send(403, {"error": "需要管理員權限"})
            return s._send(200, sv.public_settings(s.headers.get("Host")) if sv else {})
        if u.path == "/api/history":
            pid = arg("port"); hours = float(arg("hours", "24"))
            return s._send(200, {"port": pid, "points": st.history(pid, min(max(hours, 0.1), 24 * 31))})
        if u.path == "/api/mrtg":
            return s._send(200, st.mrtg(arg("port")))
        if u.path.startswith("/api/flow/"):
            if not sv: return s._send(404, {"error": "flow not available"})
            mins = max(5, min(60 * 24 * 31, int(arg("min", "60") or 60))); exp = arg("exp", "auto")
            if u.path == "/api/flow/status": return s._send(200, sv.flow_status())
            if u.path == "/api/flow/top": return s._send(200, sv.flow.top(mins, exp))
            if u.path == "/api/flow/host": return s._send(200, sv.flow.host(arg("ip"), mins, exp))
            return s._send(404, {"error": "not found"})
        if u.path == "/api/mrtg/device":
            return s._send(200, st.mrtg_device(arg("id"), arg("view", "day")))
        if u.path == "/api/mrtg/summary":
            return s._send(200, {"ports": st.mrtg_summary()})
        s._send(404, {"error": "not found"})

    def _mutating(s):
        """修改用的請求都要帶 X-Netmap 標頭（別的網站的表單或腳本帶不了，防 CSRF）。"""
        if s.headers.get("X-Netmap") != "1": s._send(403, {"error": "missing header"}); return False
        return True

    def do_POST(s):
        st, sv = s.server.store, getattr(s.server, "service", None)
        path = urllib.parse.urlparse(s.path).path
        if not s._mutating(): return
        try: body = s.body_json(1024 * 1024)
        except Exception: return s._send(400, {"error": "bad json"})
        ip = s.client_address[0]
        if path == "/api/login":
            if s.server.auth.blocked(ip): return s._send(429, {"error": "嘗試太多次，請 10 分鐘後再試"})
            h = st.settings.get("admin_hash")
            if not h or not check_pw(str(body.get("password") or ""), h):
                s.server.auth.failed(ip); time.sleep(0.6); return s._send(401, {"error": "密碼不對" if h else "還沒有設定管理密碼"})
            t = s.server.auth.new()
            return s._send(200, {"ok": True}, extra={"Set-Cookie": f"nm_a={t}; Path=/; HttpOnly; SameSite=Strict"})
        if path == "/api/logout":
            s.server.auth.drop(s._cookie("nm_a"))
            return s._send(200, {"ok": True}, extra={"Set-Cookie": "nm_a=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if not s.view_ok(): return s._send(401, {"error": "需要登入"})
        if path == "/api/projects":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            act = body.get("action"); pid = str(body.get("id") or "")
            if act == "switch":
                if not (sv.switch_project(pid) if sv else st.project_switch(pid)): return s._send(404, {"error": "找不到這個專案"})
            elif act in ("new", "copy"):
                new, err = st.project_new(body.get("name"), (pid or st.pid) if act == "copy" else None)
                if err: return s._send(400, {"error": err})
                if body.get("switch", True): (sv.switch_project(new) if sv else st.project_switch(new))
            elif act == "rename":
                err = st.project_rename(pid, body.get("name"))
                if err: return s._send(400, {"error": err})
            elif act == "delete":
                if pid == st.pid and pid != "default": (sv.switch_project("default") if sv else st.project_switch("default"))
                err = st.project_delete(pid)
                if err: return s._send(400, {"error": err})
            else: return s._send(400, {"error": "unknown action"})
            return s._send(200, st.projects())
        if path == "/api/revs/restore":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            if not st.restore(body.get("rev"), s.who()): return s._send(404, {"error": "找不到這個版本"})
            s.server.poller.ifmaps.clear()
            with st.lock: return s._send(200, {"rev": st.rev, "project": st.project})
        if path == "/api/dnscheck/run":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            po = s.server.poller
            for k in ("dns_server", "dns_domain"):
                if k in body: st.settings[k] = re.sub(r"[^\w.\-]", "", str(body[k] or ""))[:120]
            if "dns_hours" in body:
                try: st.settings["dns_hours"] = max(0, min(168, float(body["dns_hours"] or 0)))
                except (TypeError, ValueError): pass
            st.save_settings(); po.dns_force = True; po.wake.set(); return s._send(200, {"ok": True})
        if path == "/api/audit/run":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            s.server.poller.audit_force = True; s.server.poller.wake.set(); return s._send(200, {"ok": True})
        if path == "/api/audit/mark":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            if body.get("status") not in ("open", "ignored", "fixed"): return s._send(400, {"error": "bad status"})
            st.audit_mark(str(body.get("key")), body["status"]); return s._send(200, {"ok": True})
        if path == "/api/seen/forget":
            if not s.can_edit(): return s._send(403, {"error": "需要編輯權限"})
            st.seen_forget(body.get("macs") or []); return s._send(200, {"ok": True})
        if path == "/api/alerts/test":
            if not s.is_admin(): return s._send(403, {"error": "需要管理員權限"})
            if not sv: return s._send(500, {"error": "no service"})
            res = sv.notifier.deliver([{"kind": "test", "name": "netmap", "ts": int(time.time()), "detail": f"來自 {socket.gethostname()}，通知設定正常"}], only=body.get("id"))
            return s._send(200, {"results": res})
        if path in ("/api/webupdate", "/api/webupdate/reset"):
            if not s._local() or not s.is_admin(): return s._send(403, {"error": "只能在服務主機上更新網頁"})
            if path.endswith("reset"):
                try: os.remove(os.path.join(data_dir(), "web", "index.html"))
                except FileNotFoundError: pass
                return s._send(200, {"ok": True})
            v, err = web_update()
            return s._send(200 if v else 400, {"ok": True, "version": v} if v else {"error": err})
        if path.startswith("/api/scan/"):
            if not s._local(): return s._send(403, {"error": "掃描只能在服務主機上操作"})
            if not s.is_admin(): return s._send(403, {"error": "需要管理員權限"})
            if not sv: return s._send(500, {"error": "no service"})
            act = path[len("/api/scan/"):]
            if act == "start":
                ok, err = sv.scan_start(body)
                return s._send(200 if ok else 400, {"ok": True} if ok else {"error": err})
            if act == "stop": return s._send(200, {"ok": sv.scan_stop()})
            if act == "apply":
                msg, err = sv.scan_apply(body.get("how"))
                return s._send(200 if msg else 400, {"ok": True, "message": msg} if msg else {"error": err})
            return s._send(404, {"error": "not found"})
        if path == "/api/snmp/probe":
            if not s.is_admin(): return s._send(403, {"error": "需要管理員權限"})
            s.server.poller.probe_force = True; s.server.poller.wake.set()
            return s._send(200, {"ok": True, "candidates": len(probe_candidates(st.project, self_ips()))})
        if path == "/api/ping/now":
            if sv: sv.pinger.wake.set()
            return s._send(200, {"ok": True})
        s._send(404, {"error": "not found"})

    def do_PUT(s):
        st, sv = s.server.store, getattr(s.server, "service", None)
        path = urllib.parse.urlparse(s.path).path
        if not s._mutating(): return
        if path == "/api/settings":
            if not s.is_admin(): return s._send(403, {"error": "需要管理員權限"})
            try: body = s.body_json(1024 * 1024)
            except Exception: return s._send(400, {"error": "bad json"})
            err = sv.update_settings(body) if sv else "no service"
            if err: return s._send(400, {"error": err})
            return s._send(200, sv.public_settings(s.headers.get("Host")))
        if path != "/api/project": return s._send(404, {"error": "not found"})
        if not s.can_edit(): return s._send(403, {"error": "需要管理員登入才能編輯" if st.settings.get("admin_hash") else "這台電腦設定為只能在服務主機上編輯"})
        try: body = s.body_json()
        except ValueError: return s._send(413, {"error": "too large"})
        except Exception: return s._send(400, {"error": "bad json"})
        proj = body.get("project")
        if not isinstance(proj, dict) or not isinstance(proj.get("devices"), list): return s._send(400, {"error": "bad project"})
        if body.get("pid") not in (None, st.pid):   # 別人（或另一個分頁）已經切到別的專案：不能把這張圖存進去
            with st.lock: return s._send(409, {"rev": st.rev, "pid": st.pid, "project": st.project})
        if not st.set_project(proj, body.get("rev"), s.who()):
            with st.lock: return s._send(409, {"rev": st.rev, "pid": st.pid, "project": st.project})
        s.server.poller.ifmaps.clear()
        s._send(200, {"rev": st.rev})


def _guard(fn):
    """處理請求時發生例外：記錄到服務紀錄並回 500，而不是什麼都不回（瀏覽器會顯示 ERR_EMPTY_RESPONSE，也查不到原因）。"""
    def w(s):
        try: return fn(s)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError): raise
        except Exception:
            import traceback
            svc_log("處理 %s %s 時發生錯誤：\n%s" % (s.command, (s.path or "").split("?")[0], traceback.format_exc()))
            try: s._send(500, {"error": "伺服器內部錯誤，詳細內容在 C:\\ProgramData\\netmap-service.log"})
            except Exception: pass
    return w
for _m in ("do_GET", "do_POST", "do_PUT"): setattr(Handler, _m, _guard(getattr(Handler, _m)))

class Service:
    """監控服務：HTTP + 輪詢 + 心跳 + 告警。GUI 與命令列共用。"""
    def __init__(s, store=None, log=print):
        s.store = store or Store(); s.log = log
        s.poller = Poller(s.store, log, emit=s.emit); s.httpd = None; s.thread = None; s._flow = None
        s.auth = Auth()
        s.notifier = na.Notifier(lambda: s.store.settings.get("alerts"), s.resolve_channel, log)
        s.pinger = na.Pinger(lambda: [d for d in s.store.project.get("devices", []) if not d.get("demo")], lambda: s.store.settings, s.emit, log, alive=s.alive_hint, resolve=s.resolve_target)
        s._macip = (0, {}); s._dnsc = {}

    # ---------- 事件與告警 ----------
    def switch_project(s, pid):
        ok = s.store.project_switch(pid)
        if ok:
            s.poller.reset(); s.pinger.reset(); s._macip = (0, {}); s._dnsc = {}
            try: s.poller.poke()
            except Exception: pass
        return ok

    def resolve_target(s, d, ip):
        """這次心跳要 Ping 哪個 IP。
        track＝ip：固定用圖上的 IP；dns：每 5 分鐘用 DNS 查一次電腦名稱；auto（預設）：有 MAC 就跟著 MAC 走（DHCP 換 IP 也找得到）。"""
        tr = d.get("track") or "auto"
        if tr == "ip": return ip
        now = time.time()
        if tr == "dns":
            name = str(d.get("dnsname") or d.get("name") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,252}", name): return ip
            c = s._dnsc.get(name)
            if c and now - c[1] < 300: return c[0] or ip
            got = ""
            try:
                server, dom = s.poller.dns_target()[:2]
                fq = name if "." in name or not dom else f"{name}.{dom}"
                if server:
                    stt, vals = ndc.dns_query(fq, server, 1, timeout=1.5)
                    got = vals[0] if stt == "ok" and vals else ""
                if not got: got = socket.gethostbyname(fq)
            except Exception: got = ""
            s._dnsc[name] = (got, now); return got or ip
        mac = norm_mac(d.get("mac"))
        if not mac: return ip
        if now - s._macip[0] > 60:   # 每分鐘從「網路上的設備」重建一次 MAC → 最新 IP
            m = {}
            try:
                for it in s.store.seen_list():
                    if it["ip"] and not it["gone"] and now - (it["last"] or 0) < 3600: m[it["mac"]] = it["ip"]
            except Exception: pass
            s._macip = (now, m)
        return s._macip[1].get(mac) or ip

    def alive_hint(s, d, ip):
        """Ping 不通時的其他在線證據；回傳說明文字，沒有證據回傳 None。"""
        if ip in self_ips():
            nics = local_nics() or {}
            if any(ip in v["ips"] and v["up"] is not False for v in nics.values()): return "這台電腦自己"
        st = s.poller.status or {}; now = time.time()
        mac = str(d.get("mac") or "").lower().replace("-", ":")
        for dv in (st.get("devices") or {}).values():
            if not dv.get("up") or not dv.get("clients") or now - (dv.get("clients_at") or 0) > 900: continue
            for c in dv["clients"]:
                if c.get("online") and ((mac and c.get("mac") == mac) or (c.get("ip") == ip and not mac)):
                    return "路由器回報它目前在線"
        if same_lan(ip):
            m = na._mac_of(ip)
            if m and (not mac or m == mac): return "ARP 有回應（它擋了 Ping）"
        pids = {p["id"] for p in d.get("ports", [])}
        for pid in pids:
            p = (st.get("ports") or {}).get(pid)
            if p and p.get("up") and max(p.get("in") or 0, p.get("out") or 0) > 2000: return "埠上有流量"
        return None

    def emit(s, ev):
        try: s.store.add_event(ev)
        except Exception as e: s.log(f"事件寫入失敗：{e}")
        if ev["kind"] in ("down", "port_down", "newdev", "gone", "snmp_down"): s.log("事件：" + na.event_line(ev).split(" ", 1)[-1])
        s.notifier.push(ev)

    def resolve_channel(s, ch):
        c = dict(ch)
        for k in na.SECRET.get(ch.get("type"), ()): c[k] = unprotect(ch.get(k))
        return c

    def public_settings(s, host=None):
        st = s.store.settings; a = st.get("alerts") or {}
        chans = []
        for ch in a.get("channels") or []:
            c = {k: v for k, v in ch.items() if k not in na.SECRET.get(ch.get("type"), ())}
            c["secret"] = {k: bool(ch.get(k)) for k in na.SECRET.get(ch.get("type"), ())}
            c["last"] = s.notifier.results.get(ch.get("id"))
            chans.append(c)
        port = int(st.get("port", 8080)); tok = st.get("view_token") or ""
        hosts = [h for h in [((host or "").split(":")[0])] if h and not h.startswith("127.") and h != "localhost"] + [ip for ip in local_ips()]
        return {"ping_enabled": st.get("ping_enabled", True), "ping_interval": st.get("ping_interval", 30), "ping_fails": st.get("ping_fails", 2),
                "ping_slow_ms": st.get("ping_slow_ms", 200), "ping_method": na.ping_method(),
                "inv_enabled": st.get("inv_enabled", True), "inv_gone_hours": st.get("inv_gone_hours", 24),
                "snmp_autoprobe": st.get("snmp_autoprobe", True), "audit_hours": st.get("audit_hours", 6), "snmp_probe": dict(s.poller.probe_last, candidates=len(probe_candidates(s.store.project, self_ips())), next=int(s.poller.probe_t + PROBE_EVERY)),
                "alerts": {"enabled": bool(a.get("enabled")), "site": a.get("site", ""), "on": a.get("on") or {}, "channels": chans},
                "channel_types": {k: {"name": v["name"], "fields": [[f, l, sec] for f, l, sec in v["fields"]]} for k, v in na.CHANNELS.items()},
                "auth": {"has_password": bool(st.get("admin_hash")), "view_required": bool(st.get("view_required")), "lan_edit": bool(st.get("lan_edit")),
                         "view_links": [f"http://{h}:{port}/?t={tok}" for h in dict.fromkeys(hosts)] if tok else []}}

    def update_settings(s, b):
        st = s.store.settings
        num = lambda v, lo, hi, d: max(lo, min(hi, int(float(v)))) if str(v).strip() not in ("", "None") else d
        try:
            if "ping_enabled" in b: st["ping_enabled"] = bool(b["ping_enabled"])
            if "ping_interval" in b: st["ping_interval"] = num(b["ping_interval"], 5, 3600, 30)
            if "ping_fails" in b: st["ping_fails"] = num(b["ping_fails"], 1, 20, 2)
            if "ping_slow_ms" in b: st["ping_slow_ms"] = num(b["ping_slow_ms"], 10, 10000, 200)
            if "inv_enabled" in b: st["inv_enabled"] = bool(b["inv_enabled"])
            if "snmp_autoprobe" in b: st["snmp_autoprobe"] = bool(b["snmp_autoprobe"])
            if "audit_hours" in b: st["audit_hours"] = max(0, min(168, float(b["audit_hours"] or 0)))
            if "inv_gone_hours" in b: st["inv_gone_hours"] = num(b["inv_gone_hours"], 1, 24 * 90, 24)
            if "lan_edit" in b: st["lan_edit"] = bool(b["lan_edit"])
            if "view_required" in b: st["view_required"] = bool(b["view_required"])
        except (TypeError, ValueError):
            return "數字格式不對"
        pw = b.get("password")
        if isinstance(pw, dict):
            if pw.get("clear"): st["admin_hash"] = ""; s.auth.drop()
            elif pw.get("new") is not None:
                if len(str(pw["new"])) < 6: return "管理密碼至少 6 個字"
                st["admin_hash"] = hash_pw(str(pw["new"])); s.auth.drop()
        if b.get("regen_token") or (st.get("view_required") and not st.get("view_token")): st["view_token"] = secrets.token_urlsafe(18)
        if b.get("clear_token"): st["view_token"] = ""
        if isinstance(b.get("alerts"), dict):
            na_ = b["alerts"]; cur = st.setdefault("alerts", json.loads(json.dumps(DEFAULT_SETTINGS["alerts"])))
            if "enabled" in na_: cur["enabled"] = bool(na_["enabled"])
            if "site" in na_: cur["site"] = str(na_["site"])[:40]
            if isinstance(na_.get("on"), dict): cur["on"] = {k: bool(v) for k, v in na_["on"].items()}
            if isinstance(na_.get("channels"), list):
                old = {c.get("id"): c for c in cur.get("channels") or []}; out = []
                for c in na_["channels"]:
                    t = c.get("type")
                    if t not in na.CHANNELS: continue
                    cid = c.get("id") or ns.nid("ch"); prev = old.get(cid) or {}
                    o = {"id": cid, "type": t, "name": str(c.get("name") or na.CHANNELS[t]["name"])[:40], "on": c.get("on") is not False}
                    for f, _l, sec in na.CHANNELS[t]["fields"]:
                        if sec:
                            v = c.get(f)
                            o[f] = protect(str(v)) if v not in (None, "") else ("" if c.get("clear_" + f) else prev.get(f, ""))
                        else: o[f] = str(c.get(f) or "")[:300]
                    out.append(o)
                cur["channels"] = out
        s.store.save_settings()
        s.pinger.wake.set()
        return None

    # ---------- 流量明細（NetFlow／IPFIX／sFlow） ----------
    def known_ips(s):
        return {d.get("ip") for d in s.store.project.get("devices", []) if d.get("ip")}

    @property
    def flow(s):
        if s._flow is None:
            st = s.store.settings
            s._flow = nf.FlowCollector(s.store.root, int(st.get("flow_port") or 2055), int(st.get("sflow_port") or 6343), known_ips=s.known_ips, log=s.log)
        return s._flow

    def start_flow(s):
        st = s.store.settings; f = s.flow
        f.ports = {"netflow": int(st.get("flow_port") or 0), "sflow": int(st.get("sflow_port") or 0)}
        return f.start()

    def stop_flow(s):
        if s._flow and s._flow.running: s._flow.stop(); s.log("流量收集已停止")

    def flow_status(s):
        st = dict(s.flow.status()); st["enabled"] = bool(s.store.settings.get("flow_enabled")); st["collector_ips"] = local_ips()
        return st

    @property
    def running(s): return s.httpd is not None

    def start(s):
        if s.httpd: return
        port = int(s.store.settings.get("port", 8080))
        try: httpd = WebServer(("0.0.0.0", port), Handler)
        except OSError:
            if not takeover_old(port, s.log): raise
            for i in range(25):   # 舊版剛結束，埠要等一下才釋放
                try: httpd = WebServer(("0.0.0.0", port), Handler); break
                except OSError:
                    if i == 24: raise
                    time.sleep(0.2)
        httpd.daemon_threads = True; httpd.store = s.store; httpd.poller = s.poller; httpd.auth = s.auth
        httpd.service = s
        s.httpd = httpd; s.thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="http"); s.thread.start()
        s.poller.start(); s.pinger.start()
        s.log(f"服務已啟動：http://{local_ips()[0]}:{port}/")
        if s.store.settings.get("flow_enabled") and not (s._flow and s._flow.running): s.start_flow()

    # ---------- 網頁上的「掃描設備」：在服務主機上用 SNMP 掃描／網段探索，結果再套用到目前的圖 ----------
    def scan_defaults(s):
        c = s.store.settings.get("snmp") or {}
        return {"version": c.get("version", "2c"), "user": c.get("user", ""), "auth_proto": c.get("auth_proto", "SHA"), "priv_proto": c.get("priv_proto", "AES"),
                "context": c.get("context", ""), "timeout": c.get("timeout", 2.0), "targets": s.store.settings.get("last_targets", ""), "subnet": ns.local_subnet() or "",
                "saved": {"community": bool(unprotect(c.get("community", ""))) and unprotect(c.get("community", "")) != "public", "auth_key": bool(unprotect(c.get("auth_key", ""))),
                          "priv_key": bool(unprotect(c.get("priv_key", "")))}, "has_map": bool(s.store.project.get("devices"))}

    def scan_start(s, b):
        import unicodedata
        j = getattr(s, "scan", None)
        if j and j.get("running"): return None, "已經有一個掃描在進行中"
        targets = unicodedata.normalize("NFKC", str(b.get("targets") or "")).replace(",", " ").replace(";", " ").split()
        disc = b.get("mode") == "disc"
        if disc and not targets:
            sub = ns.local_subnet()
            if sub: targets = [sub]
        if not targets: return None, "請先輸入要掃描的 IP 或網段"
        if len(targets) > 64: return None, "目標太多了（最多 64 個）"
        c = s.store.settings.setdefault("snmp", {})
        ver = str(b.get("version") or "2c")
        if ver not in ("1", "2c", "3"): return None, "SNMP 版本不對"
        pick = lambda k: (b.get(k) or "").strip() if isinstance(b.get(k), str) else ""
        comm = pick("community") or unprotect(c.get("community", "")) or "public"
        akey = b.get("auth_key") or unprotect(c.get("auth_key", "")) or None; pkey = b.get("priv_key") or unprotect(c.get("priv_key", "")) or None
        if ver == "3" and not pick("user"): return None, "SNMPv3 需要填使用者"
        try: to = min(max(float(b.get("timeout") or 2.0), 0.5), 15.0)
        except (TypeError, ValueError): to = 2.0
        s.store.settings["last_targets"] = " ".join(targets)
        if b.get("remember"):
            c.update(version=ver, community=protect(comm), user=pick("user"), auth_proto=b.get("auth_proto") or "SHA", auth_key=protect(akey or ""),
                     priv_proto=b.get("priv_proto") or "AES", priv_key=protect(pkey or ""), context=pick("context"), timeout=to)
        s.store.save_settings()
        a = ns.opts(version=ver, community=comm, user=pick("user") or None, auth_proto=b.get("auth_proto") or "SHA", auth_key=akey, priv_proto=b.get("priv_proto") or "AES",
                    priv_key=pkey, context=pick("context"), timeout=to, no_follow=not b.get("follow", True), no_fdb=not b.get("fdb", True), no_neighbors=not b.get("nbr", True))
        j = s.scan = {"running": True, "mode": "disc" if disc else "snmp", "log": [], "prog": [0, 0, ""], "t0": time.time(), "project": None, "failed": [], "error": "", "stop": False, "done": False, "pid": s.store.reg.get("current")}
        def lg(m):
            j["log"].append(str(m))
            if len(j["log"]) > 2000: del j["log"][:500]
        def work():
            try:
                if disc:
                    proj = ns.discover(targets, log=lg, progress=lambda d, t, ph: j.__setitem__("prog", [d, t, ph]), stop=lambda: j["stop"], link_gateway=bool(b.get("link", True)))
                    j["project"] = proj if proj and proj.get("devices") else None; j["failed"] = []
                else:
                    proj, devs, failed = ns.run_scan(a, targets, log=lg, progress=lambda d, t, ph: j.__setitem__("prog", [d, t, ph]), stop=lambda: j["stop"])
                    j["project"] = proj; j["failed"] = [str(x) for x in (failed or [])][:50]
            except Exception as e:
                j["error"] = str(e) or e.__class__.__name__
            finally:
                j["running"] = False; j["done"] = True; j["t1"] = time.time()
        threading.Thread(target=work, daemon=True, name="scan").start()
        return True, ""

    def scan_status(s, since=0):
        j = getattr(s, "scan", None)
        if not j: return {"idle": True}
        p = j.get("project")
        return {"idle": False, "running": j["running"], "done": j["done"], "mode": j["mode"], "log": j["log"][since:], "n": len(j["log"]), "prog": j["prog"],
                "secs": round((j.get("t1") or time.time()) - j["t0"], 1), "error": j["error"], "failed": j["failed"],
                "found": {"devices": len(p.get("devices", [])), "cables": len(p.get("cables", []))} if p else None, "stopping": j["stop"] and j["running"]}

    def scan_stop(s):
        j = getattr(s, "scan", None)
        if j and j.get("running"): j["stop"] = True
        return True

    def scan_apply(s, how):
        j = getattr(s, "scan", None); st = s.store
        if not j or not j.get("project"): return None, "沒有可以套用的掃描結果"
        if j.get("pid") != st.reg.get("current"): return None, "掃描之後已經切換專案，請重新掃描"
        project = j["project"]
        if how == "replace":
            if st.project.get("devices"):
                bk = os.path.join(st.dir, "backup"); os.makedirs(bk, exist_ok=True)
                json.dump(st.project, open(os.path.join(bk, f"before-scan-{time.strftime('%Y%m%d-%H%M%S')}.json"), "w", encoding="utf-8"), ensure_ascii=False)
            st.set_project(project); msg = f"已換成這次的結果：{len(project['devices'])} 台設備、{len(project['cables'])} 條線（舊的圖已備份）"
        else:
            proj = json.loads(json.dumps(st.project))
            if str(project.get("source", "")).startswith("netmap-discover"):
                hit, new, moved = merge_discover(proj, project)
                st.set_project(proj); msg = f"已更新目前的圖：對到 {hit} 台、新增 {new} 台" + (f"、{len(moved)} 台 IP 改變" if moved else "")
            else:
                nd, npt, added, ncab = merge_snmp(proj, project, add_new=True)
                st.set_project(proj); msg = f"已更新目前的圖：對到 {nd - added} 台設備、{npt} 個埠" + (f"，新增 {added} 台（放在圖的最下面）" if added else "") + (f"，補上 {ncab} 條設備之間的線" if ncab else "")
        try: s.poller.poke()
        except Exception: pass
        j["project"] = None
        return msg, ""

    def stop(s):
        s.poller.stop(); s.pinger.stop(); s.stop_flow()
        if s.httpd:
            s.httpd.shutdown(); s.httpd.server_close(); s.httpd = None
        s.log("服務已停止")

    def urls(s):
        port = int(s.store.settings.get("port", 8080))
        return [f"http://{ip}:{port}/" for ip in local_ips()]

    def settings_url(s, section="settings"):
        return f"http://127.0.0.1:{int(s.store.settings.get('port', 8080))}/#{section}=1"

def merge_snmp(project, scanned, add_new=False):
    """把掃描結果的 SNMP 對應（host / ifIndex）套到現有的圖上，不更動版面。
    add_new：圖上還沒有的掃描設備也加進來。回傳 (對到的設備數, 對到的埠數[, 新增的設備數])。"""
    nd = npt = added = ncab = 0
    pmap = {}   # 掃描結果的埠 id → 圖上的埠 id
    for sd in scanned.get("devices", []):
        if not sd.get("snmp"): continue
        host = sd["snmp"]["host"]; hip = host.split(":")[0]
        cand = [d for d in project.get("devices", []) if (d.get("ip") and d["ip"] in (sd.get("ip"), hip)) or (d.get("name", "").lower() == sd.get("name", "").lower())]
        if not cand:
            if add_new:   # 圖上還沒有的網路設備：整台（含埠）加進來，放在最下面
                cur = project.setdefault("devices", [])
                ys = [x.get("y", 0) for x in cur] or [0]; xs = [x.get("x", 0) for x in cur] or [0]
                n = dict(sd); n["x"] = min(xs) + 260 * added; n["y"] = max(ys) + 240
                cur.append(n); added += 1; nd += 1
                for p in n.get("ports", []): pmap[p["id"]] = p["id"]
            continue
        d = cand[0]; d["snmp"] = {"host": host}; nd += 1
        by = {}
        for p in sd["ports"]:
            for k in {p["label"], *re.findall(r"\S+", p.get("note", ""))[:1]}: by.setdefault(str(k).lower(), p.get("ifIndex"))
        for p in d.get("ports", []):
            ix = by.get(str(p.get("label", "")).lower())
            if ix is not None and p.get("side") != 1: p["ifIndex"] = ix; npt += 1
        for sp in sd["ports"]:
            mp = next((p for p in d.get("ports", []) if p.get("side") != 1 and sp.get("ifIndex") is not None and p.get("ifIndex") == sp.get("ifIndex")), None) \
                 or next((p for p in d.get("ports", []) if p.get("side") != 1 and str(p.get("label", "")).lower() == str(sp.get("label", "")).lower()), None)
            if mp: pmap[sp["id"]] = mp["id"]
    if add_new:
        # 掃描找到的網路設備之間的線（LLDP 或 MAC 表推斷）：兩端在圖上都對得到、而且兩個埠都還沒接線，就補上
        cabs = project.setdefault("cables", [])
        busy = {c.get("a") for c in cabs} | {c.get("b") for c in cabs}
        for c in scanned.get("cables", []):
            a, b = pmap.get(c.get("a")), pmap.get(c.get("b"))
            if not a or not b or a == b or a in busy or b in busy: continue
            n = dict(c); n["id"] = "c" + secrets.token_hex(5); n["a"], n["b"] = a, b; n["label"] = f"S-{len(cabs) + 1:03d}"; n["wps"] = []
            cabs.append(n); busy |= {a, b}; ncab += 1
        # 掃描推斷出來、掛在圖上設備空埠後面的東西（無網管交換器、終端設備）：圖上還沒有的加進來並接好線
        sdev = {d["id"]: d for d in scanned.get("devices", [])}
        sowner = {p["id"]: d for d in scanned.get("devices", []) for p in d.get("ports", [])}
        nm = lambda m: re.sub(r"[^0-9a-f]", "", str(m or "").lower())
        cur = project.setdefault("devices", [])
        onmap = {nm(d.get("mac")): d for d in cur if nm(d.get("mac"))}
        sc = scanned.get("cables", [])
        def link(pa, pb):
            nonlocal ncab
            if pa in busy or pb in busy: return
            cabs.append({"id": "c" + secrets.token_hex(5), "a": pa, "b": pb, "label": f"S-{len(cabs) + 1:03d}", "type": "Cat6", "speed": "", "color": "#2C6FB7", "len": "", "dir": "none", "wps": []})
            busy.update((pa, pb)); ncab += 1
        def place(dv, near, k):
            dv["x"] = (near.get("x", 0) if near else 0) + 200 * (k % 6); dv["y"] = (near.get("y", 0) if near else 0) + 260 + 150 * (k // 6)
        def attach(sp_free, x, mport, near):
            """把掃描結果的設備 x 接到圖上的 mport（x 經由 sp_free 這個埠連過來）"""
            nonlocal added
            if x.get("snmp"): return
            if x["type"] == "end":
                e = onmap.get(nm(x.get("mac")))
                if e:   # 圖上已經有這台：有空埠就接過去，不重複新增
                    fp = next((p for p in e.get("ports", []) if p["id"] not in busy), None)
                    if fp: link(mport, fp["id"])
                    return
                n = json.loads(json.dumps(x)); place(n, near, added); cur.append(n); added += 1; onmap[nm(n.get("mac"))] = n
                link(mport, n["ports"][0]["id"]); return
            if x["type"] == "hub":
                kids = []
                for c in sc:
                    for mine, other in ((c["a"], c["b"]), (c["b"], c["a"])):
                        if sowner.get(mine) is x and mine != sp_free and sowner.get(other) is not None: kids.append((mine, sowner[other], other))
                if kids and all(onmap.get(nm(k[1].get("mac"))) for k in kids if k[1]["type"] == "end") and all(k[1]["type"] == "end" for k in kids): 
                    # 底下的設備圖上都有了：只把還沒接線的接到新的 Hub 上
                    if all(any(p["id"] in busy for p in onmap[nm(k[1].get("mac"))].get("ports", [])) for k in kids): return
                h = json.loads(json.dumps(x)); place(h, near, added); cur.append(h); added += 1
                hp = {p["id"]: p["id"] for p in h["ports"]}
                link(mport, hp[sp_free])
                for i, (mine, kid, other) in enumerate(kids):
                    if kid["type"] == "end": attach(other, kid, hp[mine], h)
        for c in list(sc):
            for s_end, x_end in ((c["a"], c["b"]), (c["b"], c["a"])):
                mp = pmap.get(s_end)
                if not mp or mp in busy or x_end in pmap: continue
                x = sowner.get(x_end)
                if x is None or x.get("snmp"): continue
                near = next((d for d in cur if any(p["id"] == mp for p in d.get("ports", []))), None)
                attach(x_end, x, mp, near)
    return (nd, npt, added, ncab) if add_new else (nd, npt)

def merge_discover(project, found):
    """網段探索結果併進目前的圖：用 MAC（沒有就用 IP）對應，保留原本的名稱、位置、接線與無線設定；
    只更新 IP／MAC，並加入新找到的設備。回傳 (對到, 新增, 更新 IP 的設備名稱清單)。"""
    norm = lambda m: str(m or "").lower().replace("-", ":")
    cur = project.setdefault("devices", []); hit = new = 0; moved = []
    bymac = {norm(d.get("mac")): d for d in cur if d.get("mac")}
    byip = {str(d.get("ip") or "").split("/")[0]: d for d in cur if d.get("ip")}
    idmap = {}
    xs = [d.get("x", 0) for d in cur] or [0]; ys = [d.get("y", 0) for d in cur] or [0]
    nx, ny = min(xs), max(ys) + 220
    gw_new = next((d for d in found.get("devices", []) if d.get("type") == "router"), None)
    for sd in found.get("devices", []):
        d = bymac.get(norm(sd.get("mac"))) if sd.get("mac") else None
        if d is None:
            c = byip.get(sd.get("ip"))
            if c is not None and (not c.get("mac") or not sd.get("mac") or norm(c["mac"]) == norm(sd["mac"])): d = c
        if d is not None:
            hit += 1; idmap[sd["id"]] = d["id"]
            if sd.get("ip") and d.get("ip") != sd["ip"]: moved.append(f"{d.get('name')}：{d.get('ip') or '—'} → {sd['ip']}"); d["ip"] = sd["ip"]
            if sd.get("mac") and not d.get("mac"): d["mac"] = sd["mac"]
            continue
        nd = {k: v for k, v in sd.items() if k not in ("wifi",)}
        nd["x"], nd["y"] = nx, ny; nx += 180
        if not gw_new or sd is not gw_new: nd["ports"] = sd["ports"][:1] if sd.get("type") != "router" else sd["ports"]
        idmap[sd["id"]] = nd["id"]; cur.append(nd); new += 1
        if sd.get("wifi") and idmap.get(sd["wifi"]["ap"]): nd["wifi"] = dict(sd["wifi"], ap=idmap[sd["wifi"]["ap"]])
    return hit, new, moved

def migrate_user_data():
    """安裝程式用：把「這個使用者」平常用的資料（%APPDATA%\\netmap）複製到整台電腦共用的資料夾（C:\\ProgramData\\netmap），
    並把裡面用「這個使用者」加密的密碼（dpapi:）改成「這台電腦」加密，這樣開機自動啟動的服務（SYSTEM）才讀得到。
    目的地已經有資料就不動（不覆蓋）。回傳 (狀態, 說明)。"""
    global MACHINE
    import shutil
    src = os.path.join(os.environ.get("APPDATA") or "", APP)
    MACHINE = True; dst = data_dir()
    if not os.path.isdir(src): return "none", "這個帳號沒有舊資料，不需要搬移"
    if any(os.path.exists(os.path.join(dst, f)) for f in ("project.json", "settings.json")): return "exists", "共用資料夾已經有資料，沒有覆蓋"
    for dp, _dn, fns in os.walk(src):   # 自己逐檔複製（不用 shutil.copytree：Python 3.12 在 Windows 會用 CopyFile2，部分環境不支援）
        out = os.path.join(dst, os.path.relpath(dp, src)); os.makedirs(out, exist_ok=True)
        for f in fns:
            with open(os.path.join(dp, f), "rb") as fi, open(os.path.join(out, f), "wb") as fo: shutil.copyfileobj(fi, fo)
    def walk(o):
        n = 0
        if isinstance(o, dict):
            for k, v in list(o.items()):
                if isinstance(v, str) and v.startswith("dpapi:"):
                    try: o[k] = protect(_dpapi(base64.b64decode(v[6:]), False).decode("utf-8")); n += 1
                    except Exception: pass
                else: n += walk(v)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                if isinstance(v, str) and v.startswith("dpapi:"):
                    try: o[i] = protect(_dpapi(base64.b64decode(v[6:]), False).decode("utf-8")); n += 1
                    except Exception: pass
                else: n += walk(v)
        return n
    total = 0
    for dp, _dn, fns in os.walk(dst):
        for f in fns:
            if f.endswith(".json"):
                fp = os.path.join(dp, f)
                try:
                    o = json.load(open(fp, encoding="utf-8")); c = walk(o)
                    if c: json.dump(o, open(fp, "w", encoding="utf-8"), ensure_ascii=False, indent=1); total += c
                except Exception: pass
    return "ok", f"已把舊資料複製到 {dst}，並重新加密 {total} 筆密碼"


def main():
    import argparse
    ap = argparse.ArgumentParser(description="netmap 監控服務（無視窗模式）")
    ap.add_argument("--machine", action="store_true", help="用整台電腦共用的資料夾（C:\\ProgramData\\netmap），給開機自動啟動的服務用")
    ap.add_argument("--migrate-user-data", action="store_true", help="安裝程式用：把這個使用者的舊資料搬到共用資料夾後結束")
    ap.add_argument("--port", type=int); ap.add_argument("--interval", type=int); ap.add_argument("--data")
    ap.add_argument("--flow", action="store_true", help="同時接收 NetFlow／IPFIX（UDP 2055）與 sFlow（UDP 6343）")
    ap.add_argument("--set-password", action="store_true", help="設定管理密碼（其他電腦要登入才能編輯、改設定）後結束")
    ap.add_argument("--view-link", action="store_true", help="產生（或顯示）只能檢視的連結後結束")
    a = ap.parse_args()
    if a.migrate_user_data:
        # 視窗版 exe 沒有主控台，結果寫進 %TEMP%\\racktrace-migrate.log 方便查
        lp = os.path.join(os.environ.get("TEMP") or ".", "racktrace-migrate.log")
        try: r = migrate_user_data()[1]
        except Exception as e:
            import traceback; r = "失敗：" + traceback.format_exc()
        try: open(lp, "a", encoding="utf-8").write(time.strftime("%Y-%m-%d %H:%M:%S ") + r + "\n")
        except Exception: pass
        print(r); return
    global MACHINE
    if a.machine: MACHINE = True
    st = Store(a.data)
    if a.set_password:
        import getpass
        pw = getpass.getpass("新的管理密碼（留空＝取消密碼）：")
        if pw and len(pw) < 6: print("至少 6 個字"); return
        if pw and getpass.getpass("再輸入一次：") != pw: print("兩次不一樣"); return
        st.settings["admin_hash"] = hash_pw(pw) if pw else ""; st.save_settings(); print("已設定管理密碼" if pw else "已取消管理密碼"); return
    if a.view_link:
        if not st.settings.get("view_token"): st.settings["view_token"] = secrets.token_urlsafe(18); st.save_settings()
        port = int(a.port or st.settings.get("port", 8080))
        for ip in local_ips(): print(f"http://{ip}:{port}/?t={st.settings['view_token']}")
        return
    if a.flow: st.settings["flow_enabled"] = True
    if a.port: st.settings["port"] = a.port
    if a.interval: st.settings["interval"] = a.interval
    _slog = svc_log
    if MACHINE and os.name == "nt": _slog(f"服務啟動 v{VERSION}，資料夾 {st.root}")
    sv = Service(st, log=_slog)
    try: sv.start()
    except OSError as e:   # 埠被別的程式佔用：換一個空的埠，網址檔（netmap.url）會跟著更新，捷徑照樣能開
        cur = int(st.settings.get("port", 8080)); alt = suggest_port(avoid=(cur,))
        d = port_diag(cur); sv.log(f"網頁埠 {cur} 不能用（{e}）；佔用者：{d.get('proc') or d.get('pid') or '不明'}")
        if not (MACHINE and alt): raise
        st.settings["port"] = alt; st.save_settings(); sv.log(f"改用埠 {alt}"); sv.start()
    print("網頁：", ", ".join(sv.urls()))
    if MACHINE and os.name == "nt":   # 給「開啟 RackTrace」的捷徑知道網址（資料夾本身只有管理員能讀，所以另外放一個只含網址的檔案）
        try: open(os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "netmap.url"), "w", encoding="utf-8").write(f"http://127.0.0.1:{int(st.settings.get('port', 8080))}/")
        except Exception: pass
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: sv.stop()

if __name__ == "__main__":
    main()
