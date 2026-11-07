# -*- coding: utf-8 -*-
"""
netmap 監控服務：在內網提供「機房線路對應圖」網頁，並定時用 SNMP 讀取每個埠的流量與上下線狀態。

  網頁        http://<這台電腦>:8080/
  API         GET  /api/project          目前的圖（含 rev）
              PUT  /api/project          儲存（rev 不符回 409）
              GET  /api/status           即時狀態：設備可達、每個埠 up/down、流量、使用率、錯誤
              GET  /api/history?port=..  埠的歷史流量（預設 24 小時）
              GET  /api/mrtg?port=..     MRTG 式流量圖資料（日／週／月／年）
              GET  /api/mrtg/summary     所有埠最近 24 小時的流量摘要
              GET  /api/mrtg/device?id=..&view=day|week|month|year  一台設備所有埠的流量圖
              GET  /api/flow/status | /api/flow/top?min=60 | /api/flow/host?ip=..&min=60   流量明細（NetFlow／IPFIX／sFlow）
"""
import base64, http.server, json, os, re, socket, sqlite3, sys, threading, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor

import netmap_snmp as ns
import netmap_sshmon as sm
import netmap_flow as nf

APP = "netmap"
# 主控台不是 UTF-8 時（英文版 Windows、輸出導到檔案）也不要因為中文訊息當掉
for _st in (sys.stdout, sys.stderr):
    try: _st.reconfigure(errors="replace")
    except Exception: pass

VERSION = "1.7.2"

# ───────────────────────── paths & secrets ─────────────────────────
def data_dir():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    d = os.path.join(base, APP)
    os.makedirs(d, exist_ok=True)
    return d

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
    ok = fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)) if protect else fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out))
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


# ───────────────────────── store ─────────────────────────
# MRTG 的四種解析度：(每點秒數, 保存秒數) 與 (圖名, 圖上顯示的時間範圍)
ROLLUPS = [(300, 3 * 86400), (1800, 14 * 86400), (7200, 62 * 86400), (86400, 800 * 86400)]
MRTG_VIEWS = [("day", 33 * 3600), ("week", 8 * 86400), ("month", 35 * 86400), ("year", 400 * 86400)]

# 線上版網頁偵測本機 netmap.exe：只有使用者勾選才開，只回答 /api/ping，只給這台電腦自己的瀏覽器
DETECT_ORIGINS = {"https://coloplay1.github.io"}

DEFAULT_SETTINGS = {"port": 8080, "interval": 60, "retention_days": 7, "lan_edit": False, "autostart": False, "autorun": True, "web_detect": False, "monitor_self": True,
                    "flow_enabled": False, "flow_port": 2055, "sflow_port": 6343,
                    "snmp": {"version": "2c", "community": "", "user": "", "auth_proto": "SHA", "auth_key": "", "priv_proto": "AES", "priv_key": "",
                             "context": "", "port": 161, "timeout": 2.0, "retries": 1}}

class Store:
    def __init__(s, root=None):
        s.dir = root or data_dir()
        s.lock = threading.RLock()
        s.settings = json.loads(json.dumps(DEFAULT_SETTINGS))
        p = os.path.join(s.dir, "settings.json")
        if os.path.exists(p):
            try:
                saved = json.load(open(p, encoding="utf-8"))
                snmp = {**s.settings["snmp"], **saved.get("snmp", {})}
                s.settings.update(saved); s.settings["snmp"] = snmp
            except Exception: pass
        if not s.settings["snmp"].get("community"): s.settings["snmp"]["community"] = protect("public")
        s.rev, s.project = 0, {"devices": [], "cables": [], "racks": [], "faults": []}
        pp = os.path.join(s.dir, "project.json")
        if os.path.exists(pp):
            try:
                o = json.load(open(pp, encoding="utf-8")); s.rev = int(o.get("rev", 1)); s.project = o.get("project") or s.project
            except Exception: pass
        s.db = sqlite3.connect(os.path.join(s.dir, "metrics.db"), check_same_thread=False)
        s.db.execute("PRAGMA journal_mode=WAL")
        s.db.execute("CREATE TABLE IF NOT EXISTS samples(ts INTEGER, pid TEXT, inb REAL, outb REAL, up INTEGER, ierr INTEGER, oerr INTEGER)")
        s.db.execute("CREATE INDEX IF NOT EXISTS ix_samples ON samples(pid, ts)")
        # MRTG 式彙整：每個埠在 5 分鐘／30 分鐘／2 小時／1 天的平均與最大值，保存期比原始紀錄長
        s.db.execute("CREATE TABLE IF NOT EXISTS rollup(pid TEXT, res INTEGER, ts INTEGER, n INTEGER, sin REAL, sout REAL, xin REAL, xout REAL, upn INTEGER, spd REAL, PRIMARY KEY(pid, res, ts))")
        s.db.commit()
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
            tmp = os.path.join(s.dir, "settings.json.tmp")
            json.dump(s.settings, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1); os.replace(tmp, os.path.join(s.dir, "settings.json"))

    def snmp_opts(s):
        c = s.settings["snmp"]
        return ns.opts(version=c.get("version", "2c"), community=unprotect(c.get("community")) or "public", user=c.get("user") or None,
                       auth_proto=c.get("auth_proto") or "SHA", auth_key=unprotect(c.get("auth_key")) or None, priv_proto=c.get("priv_proto") or "AES",
                       priv_key=unprotect(c.get("priv_key")) or None, context=c.get("context") or "", port=int(c.get("port") or 161),
                       timeout=float(c.get("timeout") or 2), retries=int(c.get("retries") if c.get("retries") is not None else 1))

    def set_project(s, project, base_rev=None):
        with s.lock:
            if base_rev is not None and int(base_rev) != s.rev: return False
            project = {k: project.get(k, []) for k in ("devices", "cables", "racks", "faults")}
            s.project = project; s.rev += 1
            tmp = os.path.join(s.dir, "project.json.tmp")
            json.dump({"rev": s.rev, "savedAt": time.strftime("%Y-%m-%dT%H:%M:%S"), "project": project}, open(tmp, "w", encoding="utf-8"), ensure_ascii=False)
            os.replace(tmp, os.path.join(s.dir, "project.json"))
            if s.rev % 20 == 0:  # 定期留一份備份
                bk = os.path.join(s.dir, "backup"); os.makedirs(bk, exist_ok=True)
                json.dump(project, open(os.path.join(bk, f"project-{time.strftime('%Y%m%d-%H%M%S')}.json"), "w", encoding="utf-8"), ensure_ascii=False)
            return True

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


class Poller:
    def __init__(s, store, log=print):
        s.store, s.log = store, log
        s.status = {"ts": 0, "devices": {}, "ports": {}}
        s.prev = {}          # (host, ifIndex) → (t, in, out, ierr, oerr)
        s.ifmaps = {}        # host → (time, {label → ifIndex})
        s.links = {}         # "ip:port" → sm.SshLink（保持連線）
        s.thread = None; s.stop_ev = threading.Event(); s.wake = threading.Event()
        s.running = False; s.last_cycle = 0; s.cycle_secs = 0

    def targets(s):
        out = []
        for d in s.store.project.get("devices", []):
            if d.get("monitor") is False: continue
            if (d.get("sshmon") or {}).get("host"):
                out.append((d, "ssh://" + d["sshmon"]["host"])); continue
            if not (d.get("snmp") or {}).get("host") and d.get("ip") and s.store.settings.get("monitor_self", True) and d["ip"] in self_ips():
                out.append((d, "local://" + d["ip"])); continue      # 跑 netmap.exe 的這台電腦：直接讀網卡，不需要 SNMP
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
        except Exception as e:
            res["dev"]["err"] = "沒有回應" if "timeout" in str(e) or "no response" in str(e) else str(e)
        finally:
            try: cli.close()
            except Exception: pass
        return res

    def cycle(s):
        t0 = time.time(); opts = s.store.snmp_opts(); tg = s.targets()
        devs, ports, rows = {}, {}, []
        if tg:
            with ThreadPoolExecutor(max_workers=min(16, len(tg))) as ex:
                for (d, host), r in zip(tg, ex.map(lambda x: s.poll_ssh(x[0], x[1]) if x[1].startswith("ssh://") else s.poll_local(x[0], x[1]) if x[1].startswith("local://") else s.poll_device(x[0], x[1], opts), tg)):
                    devs[d["id"]] = {**r["dev"], "host": host}; ports.update(r["ports"]); rows += r["rows"]
        s.store.add_samples(rows, {pid: p.get("speed") for pid, p in ports.items()})
        s.status = {"ts": int(time.time()), "devices": devs, "ports": ports}
        s.last_cycle = time.time(); s.cycle_secs = round(time.time() - t0, 2)
        down = [d for d in devs.values() if not d["up"]]
        s.log(f"輪詢完成：{len(devs)} 台設備（{len(down)} 台沒回應）、{len(ports)} 個埠，{s.cycle_secs} 秒")
        if int(t0) % 3600 < max(60, int(s.store.settings.get("interval", 60))): s.store.purge()

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

# ───────────────────────── HTTP ─────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"netmap/{VERSION}"
    def log_message(s, fmt, *a): pass

    def _local(s):
        ip = s.client_address[0]
        return ip.startswith("127.") or ip == "::1" or ip in local_ips()

    def _send(s, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)): body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str): body = body.encode("utf-8")
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items(): s.send_header(k, v)
        s.send_header("Cache-Control", "no-store"); s.end_headers(); s.wfile.write(body)

    def _detect_origin(s):
        """允許線上版偵測時，回傳可以放行的 Origin；否則 None。"""
        o = s.headers.get("Origin") or ""
        if s.server.store.settings.get("web_detect") and o in DETECT_ORIGINS and s._local(): return o
        return None

    def do_OPTIONS(s):
        o = s._detect_origin()
        if not o or urllib.parse.urlparse(s.path).path != "/api/ping": return s._send(403, {"error": "forbidden"})
        s._send(204, b"", "text/plain", {"Access-Control-Allow-Origin": o, "Vary": "Origin", "Access-Control-Allow-Methods": "GET",
                                          "Access-Control-Allow-Private-Network": "true", "Access-Control-Max-Age": "600"})

    def can_edit(s): return s._local() or bool(s.server.store.settings.get("lan_edit"))

    def do_GET(s):
        st, po = s.server.store, s.server.poller
        u = urllib.parse.urlparse(s.path); q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            p = web_index()
            if not p: return s._send(500, "找不到網頁檔（web/index.html）", "text/plain; charset=utf-8")
            html = open(p, encoding="utf-8").read()
            with st.lock: boot = {"rev": st.rev, "project": st.project, "interval": st.settings.get("interval", 60), "edit": s.can_edit(), "version": VERSION, "host": socket.gethostname(),
                                      "self_ips": sorted(self_ips()) if st.settings.get("monitor_self", True) else []}
            inj = "<script>window.NETMAP_SERVER=" + json.dumps(boot, ensure_ascii=False).replace("</", "<\\/") + ";</script>"
            html = html.replace("</head>", inj + "\n</head>", 1)
            return s._send(200, html, "text/html; charset=utf-8")
        if u.path == "/api/project":
            with st.lock: return s._send(200, {"rev": st.rev, "project": st.project})
        if u.path == "/api/status":
            stat = po.status
            return s._send(200, {"rev": st.rev, "ts": stat.get("ts", 0), "interval": st.settings.get("interval", 60), "running": po.running,
                                 "devices": stat.get("devices", {}), "ports": stat.get("ports", {}), "edit": s.can_edit()})
        if u.path == "/api/history":
            pid = (q.get("port") or [""])[0]; hours = float((q.get("hours") or ["24"])[0])
            return s._send(200, {"port": pid, "points": st.history(pid, min(max(hours, 0.1), 24 * 31))})
        if u.path == "/api/mrtg":
            return s._send(200, st.mrtg((q.get("port") or [""])[0]))
        if u.path.startswith("/api/flow/"):
            sv = getattr(s.server, "service", None)
            if not sv: return s._send(404, {"error": "flow not available"})
            mins = max(5, min(60 * 24 * 31, int((q.get("min") or ["60"])[0] or 60))); exp = (q.get("exp") or ["auto"])[0]
            if u.path == "/api/flow/status": return s._send(200, sv.flow_status())
            if u.path == "/api/flow/top": return s._send(200, sv.flow.top(mins, exp))
            if u.path == "/api/flow/host": return s._send(200, sv.flow.host((q.get("ip") or [""])[0], mins, exp))
            return s._send(404, {"error": "not found"})
        if u.path == "/api/mrtg/device":
            return s._send(200, st.mrtg_device((q.get("id") or [""])[0], (q.get("view") or ["day"])[0]))
        if u.path == "/api/mrtg/summary":
            return s._send(200, {"ports": st.mrtg_summary()})
        if u.path == "/api/ping":
            o = s._detect_origin()
            if o: return s._send(200, {"ok": True, "version": VERSION, "port": st.settings.get("port"), "detect": True},
                                 extra={"Access-Control-Allow-Origin": o, "Vary": "Origin", "Access-Control-Allow-Private-Network": "true"})
            return s._send(200, {"ok": True, "version": VERSION})
        s._send(404, {"error": "not found"})

    def do_PUT(s):
        st = s.server.store
        if urllib.parse.urlparse(s.path).path != "/api/project": return s._send(404, {"error": "not found"})
        if not s.can_edit(): return s._send(403, {"error": "這台電腦設定為只能在服務主機上編輯"})
        n = int(s.headers.get("Content-Length") or 0)
        if n > 50 * 1024 * 1024: return s._send(413, {"error": "too large"})
        try: body = json.loads(s.rfile.read(n).decode("utf-8"))
        except Exception: return s._send(400, {"error": "bad json"})
        proj = body.get("project")
        if not isinstance(proj, dict) or not isinstance(proj.get("devices"), list): return s._send(400, {"error": "bad project"})
        if not st.set_project(proj, body.get("rev")):
            with st.lock: return s._send(409, {"rev": st.rev, "project": st.project})
        s.server.poller.ifmaps.clear()
        s._send(200, {"rev": st.rev})

class Service:
    """監控服務：HTTP + 輪詢。GUI 與命令列共用。"""
    def __init__(s, store=None, log=print):
        s.store = store or Store(); s.log = log
        s.poller = Poller(s.store, log); s.httpd = None; s.thread = None; s._flow = None

    # ---------- 流量明細（NetFlow／IPFIX／sFlow） ----------
    def known_ips(s):
        return {d.get("ip") for d in s.store.project.get("devices", []) if d.get("ip")}

    @property
    def flow(s):
        if s._flow is None:
            st = s.store.settings
            s._flow = nf.FlowCollector(s.store.dir, int(st.get("flow_port") or 2055), int(st.get("sflow_port") or 6343), known_ips=s.known_ips, log=s.log)
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
        httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
        httpd.daemon_threads = True; httpd.store = s.store; httpd.poller = s.poller
        s.httpd = httpd; s.thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="http"); s.thread.start()
        s.poller.start(); httpd.service = s
        s.log(f"服務已啟動：http://{local_ips()[0]}:{port}/")
        if s.store.settings.get("flow_enabled") and not (s._flow and s._flow.running): s.start_flow()

    def stop(s):
        s.poller.stop(); s.stop_flow()
        if s.httpd:
            s.httpd.shutdown(); s.httpd.server_close(); s.httpd = None
        s.log("服務已停止")

    def urls(s):
        port = int(s.store.settings.get("port", 8080))
        return [f"http://{ip}:{port}/" for ip in local_ips()]

def merge_snmp(project, scanned):
    """把掃描結果的 SNMP 對應（host / ifIndex）套到現有的圖上，不更動版面。回傳 (對到的設備數, 對到的埠數)。"""
    nd = npt = 0
    for sd in scanned.get("devices", []):
        if not sd.get("snmp"): continue
        host = sd["snmp"]["host"]; hip = host.split(":")[0]
        cand = [d for d in project.get("devices", []) if (d.get("ip") and d["ip"] in (sd.get("ip"), hip)) or (d.get("name", "").lower() == sd.get("name", "").lower())]
        if not cand: continue
        d = cand[0]; d["snmp"] = {"host": host}; nd += 1
        by = {}
        for p in sd["ports"]:
            for k in {p["label"], *re.findall(r"\S+", p.get("note", ""))[:1]}: by.setdefault(str(k).lower(), p.get("ifIndex"))
        for p in d.get("ports", []):
            ix = by.get(str(p.get("label", "")).lower())
            if ix is not None and p.get("side") != 1: p["ifIndex"] = ix; npt += 1
    return nd, npt

def main():
    import argparse
    ap = argparse.ArgumentParser(description="netmap 監控服務（無視窗模式）")
    ap.add_argument("--port", type=int); ap.add_argument("--interval", type=int); ap.add_argument("--data")
    ap.add_argument("--flow", action="store_true", help="同時接收 NetFlow／IPFIX（UDP 2055）與 sFlow（UDP 6343）")
    a = ap.parse_args()
    st = Store(a.data)
    if a.flow: st.settings["flow_enabled"] = True
    if a.port: st.settings["port"] = a.port
    if a.interval: st.settings["interval"] = a.interval
    sv = Service(st); sv.start()
    print("網頁：", ", ".join(sv.urls()))
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: sv.stop()

if __name__ == "__main__":
    main()
