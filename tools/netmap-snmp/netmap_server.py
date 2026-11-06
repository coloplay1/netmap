# -*- coding: utf-8 -*-
"""
netmap 監控服務：在內網提供「機房線路對應圖」網頁，並定時用 SNMP 讀取每個埠的流量與上下線狀態。

  網頁        http://<這台電腦>:8080/
  API         GET  /api/project          目前的圖（含 rev）
              PUT  /api/project          儲存（rev 不符回 409）
              GET  /api/status           即時狀態：設備可達、每個埠 up/down、流量、使用率、錯誤
              GET  /api/history?port=..  埠的歷史流量（預設 24 小時）
"""
import base64, http.server, json, os, re, socket, sqlite3, sys, threading, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor

import netmap_snmp as ns

APP = "netmap"
# 主控台不是 UTF-8 時（英文版 Windows、輸出導到檔案）也不要因為中文訊息當掉
for _st in (sys.stdout, sys.stderr):
    try: _st.reconfigure(errors="replace")
    except Exception: pass

VERSION = "1.2.0"

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

# ───────────────────────── store ─────────────────────────
DEFAULT_SETTINGS = {"port": 8080, "interval": 60, "retention_days": 7, "lan_edit": False, "autostart": False, "autorun": True,
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
        s.db.commit()

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

    def add_samples(s, rows):
        if not rows: return
        with s.lock:
            s.db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?)", rows); s.db.commit()

    def purge(s):
        with s.lock:
            s.db.execute("DELETE FROM samples WHERE ts < ?", (int(time.time()) - int(s.settings.get("retention_days", 7)) * 86400,)); s.db.commit()

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

class Poller:
    def __init__(s, store, log=print):
        s.store, s.log = store, log
        s.status = {"ts": 0, "devices": {}, "ports": {}}
        s.prev = {}          # (host, ifIndex) → (t, in, out, ierr, oerr)
        s.ifmaps = {}        # host → (time, {label → ifIndex})
        s.thread = None; s.stop_ev = threading.Event(); s.wake = threading.Event()
        s.running = False; s.last_cycle = 0; s.cycle_secs = 0

    def targets(s):
        out = []
        for d in s.store.project.get("devices", []):
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
                    din = inc - prev[1]; dout = (outc or 0) - (prev[2] or 0)
                    if din < 0: din += wrap
                    if dout < 0: dout += wrap
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
                for (d, host), r in zip(tg, ex.map(lambda x: s.poll_device(x[0], x[1], opts), tg)):
                    devs[d["id"]] = {**r["dev"], "host": host}; ports.update(r["ports"]); rows += r["rows"]
        s.store.add_samples(rows)
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

    def poke(s):
        s.ifmaps.clear(); s.wake.set()

# ───────────────────────── HTTP ─────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"netmap/{VERSION}"
    def log_message(s, fmt, *a): pass

    def _local(s):
        ip = s.client_address[0]
        return ip.startswith("127.") or ip == "::1" or ip in local_ips()

    def _send(s, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)): body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str): body = body.encode("utf-8")
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(body)))
        s.send_header("Cache-Control", "no-store"); s.end_headers(); s.wfile.write(body)

    def can_edit(s): return s._local() or bool(s.server.store.settings.get("lan_edit"))

    def do_GET(s):
        st, po = s.server.store, s.server.poller
        u = urllib.parse.urlparse(s.path); q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            p = web_index()
            if not p: return s._send(500, "找不到網頁檔（web/index.html）", "text/plain; charset=utf-8")
            html = open(p, encoding="utf-8").read()
            with st.lock: boot = {"rev": st.rev, "project": st.project, "interval": st.settings.get("interval", 60), "edit": s.can_edit(), "version": VERSION, "host": socket.gethostname()}
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
        if u.path == "/api/ping": return s._send(200, {"ok": True, "version": VERSION})
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
        s.poller = Poller(s.store, log); s.httpd = None; s.thread = None

    @property
    def running(s): return s.httpd is not None

    def start(s):
        if s.httpd: return
        port = int(s.store.settings.get("port", 8080))
        httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
        httpd.daemon_threads = True; httpd.store = s.store; httpd.poller = s.poller
        s.httpd = httpd; s.thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="http"); s.thread.start()
        s.poller.start()
        s.log(f"服務已啟動：http://{local_ips()[0]}:{port}/")

    def stop(s):
        s.poller.stop()
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
    a = ap.parse_args()
    st = Store(a.data)
    if a.port: st.settings["port"] = a.port
    if a.interval: st.settings["interval"] = a.interval
    sv = Service(st); sv.start()
    print("網頁：", ", ".join(sv.urls()))
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: sv.stop()

if __name__ == "__main__":
    main()
