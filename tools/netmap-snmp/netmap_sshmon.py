"""netmap SSH 流量監控：給沒有 SNMP 的設備（家用路由器、Linux 主機、NAS、OpenWrt）用。

用 SSH 登入後只執行唯讀指令：
  cat /proc/net/dev                       每個介面的收送位元組、錯誤數
  /sys/class/net/*/operstate, speed       上下線與速率
  nvram get ...（只有 ASUS 等路由器）       型號與 WAN／LAN／Wi-Fi 介面名稱
連線會保持，不會每次輪詢都重新登入（避免設備記一堆登入紀錄）。
"""
import re, socket, threading, time

READ_CMD = ("cat /proc/net/dev; echo '@@NETMAP@@'; "
            "for i in /sys/class/net/*; do n=${i##*/}; echo \"$n $(cat $i/operstate 2>/dev/null) $(cat $i/speed 2>/dev/null)\"; done")
INFO_CMD = ("echo \"host=$(hostname 2>/dev/null)\"; "
            "if command -v nvram >/dev/null 2>&1; then for k in productid odmpid firmver buildno wan0_ifname lan_ifname wl0_ifname wl1_ifname wl2_ifname lan_ipaddr; do "
            "echo \"nv_$k=$(nvram get $k 2>/dev/null)\"; done; fi; "
            "if [ -r /etc/os-release ]; then grep -E '^(PRETTY_NAME|ID)=' /etc/os-release; fi; "
            "if [ -r /etc/openwrt_release ]; then grep DISTRIB_DESCRIPTION /etc/openwrt_release; fi; "
            "echo \"kernel=$(uname -sr 2>/dev/null)\"")
SKIP_IF = re.compile(r"^(lo|veth|docker|virbr\d+-nic|ifb|imq|gre0|gretap0|erspan0|sit0|ip6tnl0|ip6gre0|ip_vti0|ip6_vti0|tunl0|teql0|dummy|bonding_masters|spu_|dpsta|wds|apcli|mon\.)")


class SshError(Exception):
    pass


def split_host(host):
    """'ssh://192.168.50.1:22' / '192.168.50.1:2222' / '192.168.50.1' → ('192.168.50.1', 22)"""
    h = host[6:] if host.startswith("ssh://") else host
    if h.count(":") == 1:
        a, p = h.rsplit(":", 1)
        return a, int(p or 22)
    return h, 22


def parse_proc_net_dev(text):
    """/proc/net/dev → {ifname: (rx_bytes, tx_bytes, rx_errs, tx_errs)}"""
    out = {}
    for line in text.splitlines():
        if ":" not in line: continue
        name, rest = line.split(":", 1)
        name = name.strip(); f = rest.split()
        if not name or len(f) < 11 or not f[0].isdigit(): continue
        out[name] = (int(f[0]), int(f[8]), int(f[2]), int(f[10]))
    return out


def parse_sys(text):
    """'eth0 up 1000' 每行 → {ifname: (up|None, speed_bps)}"""
    out = {}
    for line in text.splitlines():
        p = line.split()
        if not p: continue
        st = p[1] if len(p) > 1 else ""
        sp = p[2] if len(p) > 2 else ""
        up = True if st == "up" else False if st in ("down", "lowerlayerdown") else None
        try: speed = int(sp) * 1_000_000 if int(sp) > 0 else 0
        except ValueError: speed = 0
        out[p[0]] = (up, speed)
    return out


def parse_read(text):
    a, _, b = text.partition("@@NETMAP@@")
    return parse_proc_net_dev(a), parse_sys(b)


def parse_info(text):
    kv = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1); kv[k.strip()] = v.strip().strip('"')
    return kv


class SshLink:
    """一條保持連線的 SSH；斷線時自動重連。"""

    def __init__(s, host, port, user, password, hostkey=""):
        s.host, s.port, s.user, s.password, s.hostkey = host, int(port or 22), user, password, hostkey or ""
        s.cli = None; s.lock = threading.Lock(); s.seen_key = ""

    def _connect(s, timeout=8):
        try:
            import paramiko
        except ImportError:
            raise SshError("這台電腦沒有 paramiko，無法使用 SSH（pip install paramiko）")
        cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(s.host, port=s.port, username=s.user, password=s.password, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                        look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            raise SshError("帳號或密碼錯誤")
        except (socket.timeout, TimeoutError):
            raise SshError("連線逾時（SSH 沒開，或只允許特定網路）")
        except (ConnectionRefusedError, OSError) as e:
            raise SshError(f"連不到 {s.host}:{s.port}（{getattr(e, 'strerror', None) or e}）")
        except Exception as e:
            raise SshError(str(e) or e.__class__.__name__)
        k = cli.get_transport().get_remote_server_key()
        s.seen_key = f"{k.get_name()} {k.get_base64()}"
        if s.hostkey and s.hostkey != s.seen_key:
            cli.close()
            raise SshError("設備的 SSH 主機金鑰和第一次加入時不同（設備換過，或有人冒充）。確認沒問題後請重新加入這台設備。")
        cli.get_transport().set_keepalive(30)
        s.cli = cli

    def run(s, cmd, timeout=15):
        with s.lock:
            for attempt in (0, 1):
                if s.cli is None or not s.cli.get_transport() or not s.cli.get_transport().is_active():
                    s.close_nolock(); s._connect()
                try:
                    _i, o, e = s.cli.exec_command(cmd, timeout=timeout)
                    return o.read().decode("utf-8", "replace")
                except SshError:
                    raise
                except Exception as ex:
                    s.close_nolock()
                    if attempt: raise SshError(f"指令執行失敗：{ex}")

    def close_nolock(s):
        try:
            if s.cli: s.cli.close()
        except Exception: pass
        s.cli = None

    def close(s):
        with s.lock: s.close_nolock()


def friendly_ports(info, counters, sysinfo):
    """挑出要顯示的介面，並給好懂的名稱。回傳 [(ifname, label, note)]"""
    names = {}
    nv = {k[3:]: v for k, v in info.items() if k.startswith("nv_") and v}
    if nv.get("wan0_ifname"): names[nv["wan0_ifname"]] = ("WAN", "對外（網際網路）")
    if nv.get("lan_ifname"): names[nv["lan_ifname"]] = ("LAN", "內網全部（有線＋Wi-Fi）")
    for k, lab in (("wl0_ifname", "2.4G"), ("wl1_ifname", "5G"), ("wl2_ifname", "5G-2")):
        if nv.get(k) and nv[k] not in names: names[nv[k]] = (lab, f"Wi-Fi {lab}")
    out = []
    for ifn, (lab, note) in names.items():
        if ifn in counters: out.append((ifn, lab, f"{note}（{ifn}）"))
    for ifn, c in sorted(counters.items()):
        if ifn in names or SKIP_IF.match(ifn): continue
        if c[0] + c[1] == 0: continue
        up, _sp = sysinfo.get(ifn, (None, 0))
        out.append((ifn, ifn, "" if up is not False else "（離線）"))
    return out[:32]


def probe(host, port, user, password):
    """第一次加入設備：登入、讀型號與介面。回傳 dict（不含密碼）。"""
    link = SshLink(host, port, user, password)
    try:
        info = parse_info(link.run(INFO_CMD))
        counters, sysinfo = parse_read(link.run(READ_CMD))
    finally:
        link.close()
    if not counters: raise SshError("讀不到 /proc/net/dev（這台設備可能不是 Linux，或帳號權限不足）")
    nv = {k[3:]: v for k, v in info.items() if k.startswith("nv_")}
    model = nv.get("odmpid") or nv.get("productid") or ""
    if nv.get("productid") or nv.get("firmver"):
        brand, typ = "ASUS" if re.search(r"^(RT|TUF|GT|ZenWiFi|XT|XD|RP)-?", model or "", re.I) or "asus" in info.get("kernel", "").lower() else "", "router"
        fw = " ".join(x for x in (nv.get("firmver"), nv.get("buildno")) if x)
    elif "DISTRIB_DESCRIPTION" in info or "openwrt" in info.get("ID", "").lower():
        brand, typ, fw = "OpenWrt", "router", info.get("DISTRIB_DESCRIPTION", "")
    else:
        brand, typ, fw = "", "server", info.get("PRETTY_NAME", "")
    return {"host": host, "port": int(port or 22), "hostkey": link.seen_key, "name": info.get("host") or host, "brand": brand, "model": model,
            "type": typ, "firmware": fw, "kernel": info.get("kernel", ""), "ports": friendly_ports(info, counters, sysinfo)}


def read_ports(link):
    """{ifname: (rx_bytes, tx_bytes, rx_errs, tx_errs, up, speed_bps)}"""
    counters, sysinfo = parse_read(link.run(READ_CMD))
    out = {}
    for n, c in counters.items():
        up, sp = sysinfo.get(n, (None, 0))
        out[n] = (*c, up, sp)
    return out
