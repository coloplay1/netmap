# -*- coding: utf-8 -*-
"""
收集樣本：給「log 分析告警」與「設定檔自動備份」開發用。

  LogCollector   這台電腦暫時當 Syslog（UDP 514）／SNMP Trap（UDP 162）接收器，原始內容存成檔案
  ssh_capture    用 SSH 登入設備、執行指令，把整段畫面存成檔案（密碼與機密設定自動遮蔽）

只接收與讀取，不會修改設備設定。
"""
import datetime as dt, os, re, socket, threading, time

import netmap_snmp as ns

FACILITY = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock"] + [f"local{i}" for i in range(8)]
SEVERITY = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
GENERIC_TRAP = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss", "enterpriseSpecific"]
KNOWN_OID = {"1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown", "1.3.6.1.6.3.1.1.5.4": "linkUp",
             "1.3.6.1.6.3.1.1.5.5": "authenticationFailure", "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID", "1.3.6.1.2.1.1.3.0": "sysUpTime",
             "1.3.6.1.2.1.2.2.1.1": "ifIndex", "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus", "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
             "1.3.6.1.2.1.31.1.1.1.1": "ifName"}

def decode_text(b):
    for enc in ("utf-8", "big5", "cp950"):
        try: return b.decode(enc)
        except (UnicodeDecodeError, LookupError): pass
    return b.decode("latin-1", "replace")

def parse_syslog(data):
    t = decode_text(data).rstrip("\r\n\x00")
    m = re.match(r"^<(\d{1,3})>(.*)$", t, re.S)
    if not m: return {"fac": "", "sev": "", "msg": t}
    pri = int(m.group(1))
    return {"fac": FACILITY[pri // 8] if pri // 8 < len(FACILITY) else str(pri // 8), "sev": SEVERITY[pri % 8], "msg": m.group(2)}

def _name(oid):
    for k, v in KNOWN_OID.items():
        if oid == k: return v
        if oid.startswith(k + "."): return f"{v}.{oid[len(k) + 1:]}"
    return oid

def _fmt(v):
    if isinstance(v, bytes):
        t = ns.s_(v)
        return t if t and all(c.isprintable() or c in "\t" for c in t) else "0x" + v.hex()
    if isinstance(v, ns.Raw): return f"0x{v.val.hex()}"
    return str(v)

def parse_trap(data):
    """解 SNMP v1 / v2c Trap、Inform。v3 只回傳原始資料（需要帳密才能解密）。"""
    try:
        _t, body, _ = ns._dec(data, 0)
        top = ns._seq(body)
        ver = int.from_bytes(top[0][1], "big")
        if ver == 3: return {"ver": "v3", "text": "SNMPv3 Trap（加密，需要帳密才能解開）", "vbs": []}
        comm = ns.s_(top[1][1]); pt, pbody = top[2]
        f = ns._seq(pbody)
        if pt == 0xA4:  # v1 Trap-PDU
            ent = ns._oid_str(f[0][1]); agent = ".".join(str(x) for x in f[1][1]); gen = int.from_bytes(f[2][1], "big"); spec = int.from_bytes(f[3][1], "big")
            vbs = [(ns._oid_str(ov), ns._val(vt, vv)) for _x, vb in ns._seq(f[5][1]) for (ot, ov), (vt, vv) in [ns._seq(vb)]]
            name = GENERIC_TRAP[gen] if gen < len(GENERIC_TRAP) else str(gen)
            if gen == 6: name = f"enterpriseSpecific {ent}.{spec}"
            return {"ver": "v1", "community": comm, "agent": agent, "trap": name, "vbs": vbs}
        vbs = [(ns._oid_str(ov), ns._val(vt, vv)) for _x, vb in ns._seq(f[3][1]) for (ot, ov), (vt, vv) in [ns._seq(vb)]]
        trap = next((str(v) for o, v in vbs if o == "1.3.6.1.6.3.1.1.4.1.0"), "")
        return {"ver": "v2c", "community": comm, "trap": KNOWN_OID.get(trap, trap), "inform": pt == 0xA6, "vbs": vbs}
    except Exception as e:
        return {"ver": "?", "text": f"無法解析：{e}", "vbs": []}

def trap_text(d):
    if d.get("text"): return d["text"]
    head = f"[{d['ver']}] {d.get('trap', '')}" + (f" agent={d['agent']}" if d.get("agent") else "")
    vb = "；".join(f"{_name(o)}={_fmt(v)}" for o, v in d["vbs"] if o not in ("1.3.6.1.6.3.1.1.4.1.0",))
    return head + (f"  {vb}" if vb else "")

class LogCollector:
    """暫時的 Syslog / Trap 接收器：原始內容 + 解析結果寫到樣本檔，並把每一筆交給 on_event。"""
    def __init__(s, folder, on_event=print, syslog_port=514, trap_port=162):
        s.folder = folder; os.makedirs(folder, exist_ok=True)
        s.on_event = on_event; s.ports = {"syslog": syslog_port, "trap": trap_port}
        s.socks = {}; s.threads = []; s.stop_ev = threading.Event(); s.files = {}; s.counts = {"syslog": 0, "trap": 0}; s.sources = {}
        s.started = None; s.lock = threading.Lock()

    def start(s, syslog=True, trap=True):
        s.stop_ev.clear(); s.started = time.time(); stamp = time.strftime("%Y%m%d-%H%M%S"); errors = []
        for kind, on in (("syslog", syslog), ("trap", trap)):
            if not on: continue
            try:
                sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sk.bind(("0.0.0.0", s.ports[kind])); sk.settimeout(0.5)
            except OSError as e:
                errors.append(f"UDP {s.ports[kind]}（{'Syslog' if kind == 'syslog' else 'Trap'}）無法開啟：{e}。可能有其他 log 軟體佔用，或需要防火牆允許。"); continue
            s.socks[kind] = sk
            path = os.path.join(s.folder, f"{kind}-{stamp}.log")
            s.files[kind] = open(path, "a", encoding="utf-8")
            s.files[kind].write(f"# netmap {kind} 樣本，開始 {dt.datetime.now().isoformat(timespec='seconds')}，UDP {s.ports[kind]}\n# 格式：時間<TAB>來源 IP<TAB>解析結果<TAB>原始內容（hex 只有 Trap）\n")
            th = threading.Thread(target=s._loop, args=(kind,), daemon=True); th.start(); s.threads.append(th)
        return errors

    def _loop(s, kind):
        sk = s.socks[kind]
        while not s.stop_ev.is_set():
            try: data, addr = sk.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            now = dt.datetime.now().isoformat(timespec="milliseconds"); src = addr[0]
            if kind == "syslog":
                d = parse_syslog(data); summary = f"{d['fac']}.{d['sev']}  {d['msg']}" if d["sev"] else d["msg"]; raw = decode_text(data).rstrip()
            else:
                d = parse_trap(data); summary = trap_text(d); raw = data.hex()
            with s.lock:
                s.counts[kind] += 1; s.sources[src] = s.sources.get(src, 0) + 1
                f = s.files.get(kind)
                if f: f.write(f"{now}\t{src}\t{summary.replace(chr(10), ' ')}\t{raw.replace(chr(10), ' ')}\n"); f.flush()
            try: s.on_event(kind, src, summary)
            except Exception: pass

    def stop(s):
        s.stop_ev.set()
        for sk in s.socks.values():
            try: sk.close()
            except OSError: pass
        for th in s.threads: th.join(1)
        with s.lock:
            for f in s.files.values():
                try: f.write(f"# 結束 {dt.datetime.now().isoformat(timespec='seconds')}\n"); f.close()
                except Exception: pass
        paths = [f.name for f in s.files.values()]
        s.socks, s.threads, s.files = {}, [], {}
        return paths

def send_test_syslog(host="127.0.0.1", port=514):
    msg = f"<134>{time.strftime('%b %d %H:%M:%S')} netmap-test: 這是 netmap 的測試訊息 test message"
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sk.sendto(msg.encode("utf-8"), (host, port)); sk.close()

def send_test_trap(host="127.0.0.1", port=162, community="public"):
    """送一個 v2c linkDown Trap（ifIndex 1），用來確認接收器正常。"""
    vbs = [("1.3.6.1.2.1.1.3.0", ns._tlv(0x43, (12345).to_bytes(2, "big"))), ("1.3.6.1.6.3.1.1.4.1.0", ns._oid("1.3.6.1.6.3.1.1.5.3")),
           ("1.3.6.1.2.1.2.2.1.1.1", ns._int(1)), ("1.3.6.1.2.1.2.2.1.8.1", ns._int(2))]
    body = b"".join(ns._tlv(0x30, ns._oid(o) + v) for o, v in vbs)
    pdu = ns._tlv(0xA7, ns._int(4242) + ns._int(0) + ns._int(0) + ns._tlv(0x30, body))
    msg = ns._tlv(0x30, ns._int(1) + ns._tlv(0x04, community.encode()) + pdu)
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sk.sendto(msg, (host, port)); sk.close()

# ───────────────────────── SSH 登入紀錄 ─────────────────────────
PROFILES = {
    "auto":     {"name": "自動判斷", "paging": [], "cmds": []},
    "cisco":    {"name": "Cisco IOS / IOS-XE / CBS", "paging": ["terminal length 0"], "cmds": ["show version", "show running-config"]},
    "fortigate": {"name": "Fortinet FortiGate", "paging": [], "cmds": ["get system status", "show full-configuration"]},
    "aruba":    {"name": "Aruba / HPE ProCurve / Aruba CX", "paging": ["no page"], "cmds": ["show version", "show running-config"]},
    "juniper":  {"name": "Juniper Junos", "paging": ["set cli screen-length 0"], "cmds": ["show version", "show configuration | display set"]},
    "mikrotik": {"name": "MikroTik RouterOS", "paging": [], "cmds": ["/system resource print", "/export"]},
    "huawei":   {"name": "Huawei / H3C", "paging": ["screen-length 0 temporary"], "cmds": ["display version", "display current-configuration"]},
    "tplink":   {"name": "TP-Link JetStream / Omada", "paging": ["terminal length 0"], "cmds": ["show system-info", "show running-config"]},
    "linux":    {"name": "Linux / 華碩等家用路由器", "paging": [], "cmds": ["uname -a", "cat /proc/version", "nvram get productid", "nvram get firmver"]},
}
PROMPT = re.compile(r"(?:^|\n)[^\n]{0,80}?[\w\-.)\]~]\s?[#>$%]\s?$")
MORE = re.compile(r"(--\s?More\s?--|<--- More --->|-- MORE --|---- More ----|Press any key to continue|\(more\)|--More-- or \(q\)uit|More: <space>)", re.I)
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][AB012]|\r")

SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(password|passwd|secret|pre-shared-key|psk|passphrase|private-key|key-string|auth-key|priv-key|authentication-key|md5|shared-secret)(\s+(?:\d+\s+|ENC\s+|encrypted\s+|cipher\s+|sha\d*\s+|md5\s+)?)(\S+)"), r"\1\2***"),
    (re.compile(r"(?i)\b(snmp-server community|community)(\s+)(\S+)"), r"\1\2***"),
    (re.compile(r"(?i)\b(set (?:password|passwd|psksecret|secret|private-key|ppk-secret|auth-pwd|priv-pwd|key|community)\s+)(ENC\s+)?(\S+)"), r"\1\2***"),
    (re.compile(r"(?im)^(\s*[\w.-]*(?:passwd|password|psk|secret|key|token|community)[\w.-]*=)(.+)$"), r"\1***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "-----BEGIN PRIVATE KEY----- *** -----END PRIVATE KEY-----"),
]
def mask_secrets(text, extra=()):
    for p, rep in SECRET_PATTERNS: text = p.sub(rep, text)
    for x in extra:
        if x and len(x) >= 3: text = text.replace(x, "***")
    return text

def guess_profile(banner):
    t = banner.lower()
    if "fortigate" in t or re.search(r"\n[\w-]+ (\(\w+\) )?# ?$", banner) and "fortinet" in t: return "fortigate"
    if "routeros" in t or "mikrotik" in t: return "mikrotik"
    if "junos" in t or "juniper" in t: return "juniper"
    if "huawei" in t or "h3c" in t or re.search(r"<[\w-]+>\s*$", banner): return "huawei"
    if "procurve" in t or "aruba" in t or "hpe" in t: return "aruba"
    if "busybox" in t or "asuswrt" in t or re.search(r"[\w-]+@[\w-]+:[^\n]*[#$] ?$", banner): return "linux"
    if "jetstream" in t or "tp-link" in t: return "tplink"
    return "cisco"

def ssh_capture(host, user, password, profile="auto", port=22, enable_pw="", commands=None, log=print, timeout=12, idle=2.5, max_wait=120):
    """登入、關分頁、執行指令，回傳 (遮蔽後的完整紀錄, 偵測到的 profile)。"""
    try:
        import paramiko
    except Exception as e:
        raise RuntimeError("需要 paramiko 套件（pip install paramiko）") from e
    cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log(f"連線 {host}:{port}…")
    cli.connect(host, port=port, username=user, password=password, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                look_for_keys=False, allow_agent=False)
    tr = cli.get_transport(); remote = tr.remote_version if tr else ""
    ch = cli.invoke_shell(width=250, height=1000); ch.settimeout(0.3)
    buf = [f"# netmap 登入紀錄  {host}:{port}  使用者 {user}  {dt.datetime.now().isoformat(timespec='seconds')}\n# SSH 伺服器版本：{remote}\n"]

    def read_until_prompt(wait=max_wait):
        out, t0, last = "", time.time(), time.time()
        while time.time() - t0 < wait:
            try:
                chunk = ch.recv(65535)
                if not chunk: break
                txt = ANSI.sub("", decode_text(chunk)); out += txt; last = time.time()
                if MORE.search(out[-120:]):
                    out = MORE.sub("", out); ch.send(" "); continue
                if re.search(r"(?i)password:\s*$", out[-40:]): return out, "password"
                if PROMPT.search(out[-200:]) and time.time() - last < 0.05: pass
            except socket.timeout:
                if PROMPT.search(out[-200:]) and time.time() - last > 0.6: return out, "prompt"
                if time.time() - last > idle and out: return out, "idle"
        return out, "timeout"

    banner, _st = read_until_prompt(20); buf.append(banner)
    prof = guess_profile(remote + "\n" + banner) if profile == "auto" else profile
    P = PROFILES.get(prof, PROFILES["cisco"])
    log(f"設備類型：{P['name']}")
    if prof in ("cisco", "tplink") and banner.rstrip().endswith(">") and enable_pw:
        ch.send("enable\n"); o, st = read_until_prompt(10); buf.append(o)
        if st == "password": ch.send(enable_pw + "\n"); o, st = read_until_prompt(10); buf.append(o)
    for c in P["paging"]:
        ch.send(c + "\n"); o, _ = read_until_prompt(15); buf.append(o)
    for c in (commands or P["cmds"]):
        log(f"執行：{c}")
        ch.send(c + "\n"); o, st = read_until_prompt(max_wait); buf.append(o)
        if st == "timeout": log("  （等待逾時，可能指令輸出很長或提示字元判斷不到）")
    try: ch.send("exit\n"); time.sleep(0.3)
    except Exception: pass
    cli.close()
    text = "".join(buf).replace("\r", "")
    return mask_secrets(text, [password, enable_pw]), prof
