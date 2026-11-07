#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netmap-snmp：用 SNMP 掃描網路設備，產生 RackTrace（機房線路對應圖）可匯入的 JSON。
https://coloplay1.github.io/netmap/

讀取（唯讀，不會修改設備設定）：
  SNMPv2-MIB    系統名稱、描述、位置
  IF-MIB        埠名稱、速率、狀態、描述
  ENTITY-MIB    型號、序號
  LLDP-MIB      相鄰設備與對接的埠（畫線的核心）
  CISCO-CDP-MIB Cisco 相鄰設備
  BRIDGE / Q-BRIDGE-MIB   MAC 表、VLAN（PVID、Trunk）
  POWER-ETHERNET-MIB      PoE
  IEEE8023-LAG-MIB        LACP
  IP-MIB        ARP 表（推斷終端設備 IP）

SNMP v1 / v2c 只用 Python 標準函式庫；SNMP v3 需要 `pip install pysnmp`。
"""
import argparse, concurrent.futures as cf, datetime as dt, ipaddress, json, os, random, re, socket, sys, time

VERSION = "1.2.0"
# 主控台不是 UTF-8 時（英文版 Windows、輸出導到檔案）也不要因為中文訊息當掉
for _st in (sys.stdout, sys.stderr):
    try: _st.reconfigure(errors="replace")
    except Exception: pass

APP_URL = "https://coloplay1.github.io/netmap/"

# ───────────────────────── BER / SNMP v1, v2c ─────────────────────────
class Raw:  # typed value that keeps its ASN.1 tag
    __slots__ = ("tag", "val")
    def __init__(s, tag, val): s.tag, s.val = tag, val
    def __repr__(s): return f"Raw({s.tag:#x},{s.val!r})"

NO_SUCH = {0x80, 0x81, 0x82}

def _len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _tlv(tag, body): return bytes([tag]) + _len(len(body)) + body

def _int(v):
    n = (v.bit_length() + 8) // 8 or 1
    return _tlv(0x02, v.to_bytes(n, "big", signed=True))

def _oid(o):
    p = [int(x) for x in o.strip(".").split(".")]
    out = bytearray([p[0] * 40 + p[1]])
    for x in p[2:]:
        enc = [x & 0x7F]; x >>= 7
        while x: enc.insert(0, 0x80 | (x & 0x7F)); x >>= 7
        out += bytes(enc)
    return _tlv(0x06, bytes(out))

def _dec(buf, i):
    tag = buf[i]; i += 1; ln = buf[i]; i += 1
    if ln & 0x80:
        k = ln & 0x7F; ln = int.from_bytes(buf[i:i + k], "big"); i += k
    return tag, buf[i:i + ln], i + ln

def _seq(buf):
    out, i = [], 0
    while i < len(buf):
        t, v, i = _dec(buf, i); out.append((t, v))
    return out

def _oid_str(b):
    first = b[0]; parts = [first // 40, first % 40]; n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80: parts.append(n); n = 0
    return ".".join(map(str, parts))

def _val(tag, v):
    if tag == 0x02: return int.from_bytes(v, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46): return int.from_bytes(v, "big", signed=False)
    if tag == 0x04: return v
    if tag == 0x06: return _oid_str(v)
    if tag == 0x40: return ".".join(str(x) for x in v)
    if tag == 0x05: return None
    return Raw(tag, v)

class SnmpError(Exception): pass

class V2Client:
    """Minimal SNMP v1/v2c client (GET, GETNEXT, GETBULK, walk)."""
    def __init__(s, host, community="public", version="2c", port=161, timeout=1.5, retries=1):
        s.host, s.port, s.comm = host, port, community.encode()
        s.ver = 0 if version == "1" else 1
        s.timeout, s.retries = timeout, retries
        s.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sock.settimeout(timeout)

    def close(s): s.sock.close()

    def _req(s, pdu_tag, oids, a=0, b=0):
        rid = random.randint(1, 0x7FFFFFFF)
        vbs = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
        pdu = _tlv(pdu_tag, _int(rid) + _int(a) + _int(b) + _tlv(0x30, vbs))
        msg = _tlv(0x30, _int(s.ver) + _tlv(0x04, s.comm) + pdu)
        for _ in range(s.retries + 1):
            try:
                s.sock.sendto(msg, (s.host, s.port))
                while True:
                    data, _addr = s.sock.recvfrom(65535)
                    t, body, _ = _dec(data, 0)
                    top = _seq(body)
                    if len(top) < 3: continue
                    pt, pbody = top[2]
                    f = _seq(pbody)
                    if int.from_bytes(f[0][1], "big", signed=True) != rid: continue
                    err = int.from_bytes(f[1][1], "big")
                    if err and pdu_tag != 0xA5: raise SnmpError(f"error-status {err}")
                    res = []
                    for _t, vb in _seq(f[3][1]):
                        (ot, ov), (vt, vv) = _seq(vb)
                        res.append((_oid_str(ov), vt, _val(vt, vv)))
                    return res
            except socket.timeout:
                continue
        raise SnmpError("timeout")

    def get(s, oids):
        out = {}
        for o, t, v in s._req(0xA0, oids):
            if t not in NO_SUCH: out[o] = v
        return out

    def walk(s, base, max_rows=20000):
        base = base.strip("."); pre = base + "."; cur = base; out = {}
        while len(out) < max_rows:
            if s.ver == 0: rows = s._req(0xA1, [cur])
            else: rows = s._req(0xA5, [cur], 0, 30)
            if not rows: break
            done = False
            for o, t, v in rows:
                if t in NO_SUCH or not o.startswith(pre): done = True; break
                if o in out: done = True; break
                out[o] = v; cur = o
            if done: break
        return out

class V3Client:
    """SNMP v3 via pysnmp (optional dependency)."""
    def __init__(s, host, user, auth_proto, auth_key, priv_proto, priv_key, port=161, timeout=2, retries=1, context=""):
        try:
            import asyncio
            from pysnmp.hlapi.v3arch import asyncio as h
        except Exception as e:
            raise SnmpError("SNMP v3 需要 pysnmp：請先執行 pip install pysnmp") from e
        s.h, s.asyncio = h, asyncio
        ap = {"MD5": h.usmHMACMD5AuthProtocol, "SHA": h.usmHMACSHAAuthProtocol, "SHA256": h.usmHMAC192SHA256AuthProtocol,
              "SHA512": h.usmHMAC384SHA512AuthProtocol, None: h.usmNoAuthProtocol}
        pp = {"DES": h.usmDESPrivProtocol, "AES": h.usmAesCfb128Protocol, "AES256": h.usmAesCfb256Protocol, None: h.usmNoPrivProtocol}
        s.user = h.UsmUserData(user, auth_key or None, priv_key or None,
                               authProtocol=ap.get(auth_proto, h.usmHMACSHAAuthProtocol) if auth_key else h.usmNoAuthProtocol,
                               privProtocol=pp.get(priv_proto, h.usmAesCfb128Protocol) if priv_key else h.usmNoPrivProtocol)
        s.host, s.port, s.timeout, s.retries = host, port, timeout, retries
        s.ctx = h.ContextData(contextName=context) if context else h.ContextData()
        s.engine = h.SnmpEngine(); s.loop = asyncio.new_event_loop()

    def close(s):
        try: s.engine.close_dispatcher()
        except Exception: pass
        try:
            pend = [t for t in s.asyncio.all_tasks(s.loop) if not t.done()]
            for t in pend: t.cancel()
            if pend: s.loop.run_until_complete(s.asyncio.gather(*pend, return_exceptions=True))
            s.loop.close()
        except Exception: pass

    def _conv(s, v):
        cls = v.__class__.__name__
        if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"): return None
        if cls == "OctetString": return bytes(v.asOctets())
        if cls == "ObjectIdentifier": return str(v)
        if cls == "IpAddress": return ".".join(str(x) for x in v.asNumbers())
        try: return int(v)
        except Exception: return str(v)

    async def _target(s): return await s.h.UdpTransportTarget.create((s.host, s.port), timeout=s.timeout, retries=s.retries)

    def get(s, oids):
        h = s.h
        async def run():
            ei, es, _ix, vbs = await h.get_cmd(s.engine, s.user, await s._target(), s.ctx, *[h.ObjectType(h.ObjectIdentity(o)) for o in oids])
            if ei: raise SnmpError(str(ei))
            return {str(o): s._conv(v) for o, v in vbs if s._conv(v) is not None}
        return s.loop.run_until_complete(run())

    def walk(s, base, max_rows=20000):
        h = s.h
        async def run():
            out = {}
            async for ei, es, _ix, vbs in h.bulk_walk_cmd(s.engine, s.user, await s._target(), s.ctx, 0, 25,
                                                          h.ObjectType(h.ObjectIdentity(base)), lexicographicMode=False):
                if ei: raise SnmpError(str(ei))
                for o, v in vbs:
                    c = s._conv(v)
                    if c is not None: out[str(o)] = c
                if len(out) >= max_rows: break
            return out
        return s.loop.run_until_complete(run())

# ───────────────────────── OIDs ─────────────────────────
SYS = {"descr": "1.3.6.1.2.1.1.1.0", "oid": "1.3.6.1.2.1.1.2.0", "name": "1.3.6.1.2.1.1.5.0", "loc": "1.3.6.1.2.1.1.6.0"}
IF_DESCR, IF_TYPE, IF_SPEED, IF_MAC, IF_OPER = ("1.3.6.1.2.1.2.2.1." + x for x in ("2", "3", "5", "6", "8"))
IF_NAME, IF_HSPEED, IF_ALIAS = ("1.3.6.1.2.1.31.1.1.1." + x for x in ("1", "15", "18"))
IP_ADDR_IF = "1.3.6.1.2.1.4.20.1.2"
ARP = "1.3.6.1.2.1.4.22.1.2"
ENT_CLASS, ENT_SERIAL, ENT_MFG, ENT_MODEL = ("1.3.6.1.2.1.47.1.1.1.1." + x for x in ("5", "11", "12", "13"))
LLDP_LOC_PORTID, LLDP_LOC_PORTDESC = "1.0.8802.1.1.2.1.3.7.1.3", "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_LOC_CAP = "1.0.8802.1.1.2.1.3.6.0"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN = "1.0.8802.1.1.2.1.4.2.1.3"
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"
BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
VLAN_EGRESS, VLAN_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.4", "1.3.6.1.2.1.17.7.1.4.2.1.5"
POE_ADMIN = "1.3.6.1.2.1.105.1.1.1.3"
LAG_ATTACHED = "1.2.840.10006.300.43.1.2.1.1.13"
IF_STACK = "1.3.6.1.2.1.31.1.2.1.3"   # ifStackStatus：上層介面.下層介面（Port-channel → 成員埠）

ENTERPRISE = {9: "Cisco", 12356: "Fortinet", 25461: "Palo Alto Networks", 8741: "SonicWall", 2636: "Juniper", 14823: "Aruba (HPE)",
              41112: "Ubiquiti", 11863: "TP-Link", 171: "D-Link", 4526: "Netgear", 890: "Zyxel", 14988: "MikroTik", 2011: "Huawei",
              25506: "H3C", 1916: "Extreme Networks", 30065: "Arista", 674: "Dell", 6574: "Synology", 24681: "QNAP", 2620: "Check Point",
              11: "HP", 8072: "", 29671: "Cisco Meraki", 25053: "Ruckus", 8691: "Moxa", 10297: "Advantech"}
DESCR_BRANDS = [("fortigate", "Fortinet"), ("fortiswitch", "Fortinet"), ("fortinet", "Fortinet"), ("pan-os", "Palo Alto Networks"), ("palo alto", "Palo Alto Networks"),
                ("sonicwall", "SonicWall"), ("sonicos", "SonicWall"), ("sophos", "Sophos"), ("watchguard", "WatchGuard"), ("check point", "Check Point"),
                ("meraki", "Cisco Meraki"), ("cisco", "Cisco"), ("junos", "Juniper"), ("juniper", "Juniper"), ("aruba", "Aruba (HPE)"), ("procurve", "Aruba (HPE)"),
                ("unifi", "Ubiquiti"), ("ubiquiti", "Ubiquiti"), ("edgeos", "Ubiquiti"), ("tp-link", "TP-Link"), ("omada", "TP-Link"), ("d-link", "D-Link"),
                ("netgear", "Netgear"), ("zyxel", "Zyxel"), ("routeros", "MikroTik"), ("mikrotik", "MikroTik"), ("huawei", "Huawei"), ("h3c", "H3C"),
                ("comware", "H3C"), ("draytek", "DrayTek"), ("vigor", "DrayTek"), ("ruckus", "Ruckus"), ("extreme", "Extreme Networks"), ("arista", "Arista"),
                ("moxa", "Moxa"), ("synology", "Synology"), ("qnap", "QNAP"), ("hikvision", "Hikvision"), ("vivotek", "VIVOTEK"), ("dahua", "Dahua"),
                ("axis", "Axis"), ("yealink", "Yealink"), ("grandstream", "Grandstream"), ("brother", "Brother"), ("epson", "Epson"), ("canon", "Canon"),
                ("hp ", "HP"), ("jetdirect", "HP"), ("lexmark", "Lexmark"), ("ricoh", "Ricoh"), ("kyocera", "Kyocera"), ("windows", "Microsoft"), ("linux", "")]
FW_BRANDS = {"Fortinet", "Palo Alto Networks", "SonicWall", "Sophos", "WatchGuard", "Check Point"}

def s_(v):
    if isinstance(v, bytes):
        try: t = v.decode("utf-8")
        except UnicodeDecodeError: t = v.decode("latin-1")
        return t.replace("\x00", "").strip()
    return "" if v is None else str(v).strip()

def mac_of(v):
    if isinstance(v, bytes) and len(v) == 6: return ":".join(f"{x:02X}" for x in v)
    t = s_(v)
    m = re.sub(r"[^0-9A-Fa-f]", "", t)
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)).upper() if len(m) == 12 else ""

def ip_of(v):
    if isinstance(v, bytes) and len(v) == 4: return ".".join(str(x) for x in v)
    t = s_(v); return t if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", t) else ""

def idx(oid, base): return oid[len(base) + 1:]
def by_index(table, base): return {idx(o, base): v for o, v in table.items()}

SHORT = [(r"^TenGigabitEthernet", "Te"), (r"^TwentyFiveGigE", "Twe"), (r"^FortyGigabitEthernet", "Fo"), (r"^HundredGigE", "Hu"),
         (r"^GigabitEthernet", "Gi"), (r"^FastEthernet", "Fa"), (r"^Ethernet", "Eth"), (r"^ethernet", "eth"), (r"^Port ", "")]
def short_if(n):
    for a, b in SHORT: n = re.sub(a, b, n)
    return n.strip()

def bits_ports(octets):  # PortList bitmap → set of bridge port numbers
    out = set()
    if not isinstance(octets, (bytes, bytearray)): return out
    for i, byte in enumerate(octets):
        for b in range(8):
            if byte & (0x80 >> b): out.add(i * 8 + b + 1)
    return out

# ───────────────────────── collect one device ─────────────────────────
def collect(cli, host, want_fdb=True, log=print):
    d = {"host": host}
    sysv = cli.get(list(SYS.values()))
    if not sysv: raise SnmpError("no response")
    d["sysDescr"] = s_(sysv.get(SYS["descr"])); d["sysName"] = s_(sysv.get(SYS["name"])) or host
    d["sysOid"] = s_(sysv.get(SYS["oid"])); d["sysLoc"] = s_(sysv.get(SYS["loc"]))
    def W(base):
        try: return by_index(cli.walk(base), base)
        except SnmpError: return {}
    names, descr, types = W(IF_NAME), W(IF_DESCR), W(IF_TYPE)
    hs, sp, oper, alias, macs = W(IF_HSPEED), W(IF_SPEED), W(IF_OPER), W(IF_ALIAS), W(IF_MAC)
    ifs = {}
    for i in set(descr) | set(names):
        nm = s_(names.get(i)) or s_(descr.get(i))
        speed = (hs.get(i) or 0) * 1_000_000 or (sp.get(i) or 0)
        ifs[i] = {"name": nm, "descr": s_(descr.get(i)), "type": types.get(i, 0), "speed": speed, "up": oper.get(i) == 1,
                  "alias": s_(alias.get(i)), "mac": mac_of(macs.get(i))}
    d["ifs"] = ifs
    ipif = W(IP_ADDR_IF); d["ips"] = {k: str(v) for k, v in ipif.items()}
    ent_class, ent_model, ent_mfg, ent_ser = W(ENT_CLASS), W(ENT_MODEL), W(ENT_MFG), W(ENT_SERIAL)
    chassis = sorted([k for k, v in ent_class.items() if v == 3], key=lambda x: int(x.split(".")[0]))
    pick = chassis[0] if chassis else (sorted(ent_model, key=lambda x: int(x.split(".")[0]))[0] if ent_model else None)
    d["model"] = s_(ent_model.get(pick)) if pick else ""; d["mfg"] = s_(ent_mfg.get(pick)) if pick else ""; d["serial"] = s_(ent_ser.get(pick)) if pick else ""
    try: cap = cli.get([LLDP_LOC_CAP]).get(LLDP_LOC_CAP)
    except SnmpError: cap = None
    d["caps"] = cap if isinstance(cap, (bytes, bytearray)) else b""
    # LLDP
    loc_id, loc_desc = W(LLDP_LOC_PORTID), W(LLDP_LOC_PORTDESC)
    rem = W(LLDP_REM); man = W(LLDP_REM_MAN)
    nbr = {}
    for k, v in rem.items():
        col, rest = k.split(".", 1)
        tm, lport, ridx = rest.split(".", 2)
        e = nbr.setdefault((lport, ridx), {"lport": lport})
        e[{"4": "chSub", "5": "chId", "6": "pSub", "7": "pId", "8": "pDesc", "9": "sysName", "10": "sysDesc", "12": "caps"}.get(col, "c" + col)] = v
    for k in man:  # index: timeMark.localPort.remIndex.addrSubtype.addrLen.addr...
        p = k.split(".")
        if len(p) >= 9 and p[3] == "1" and p[4] == "4":
            e = nbr.get((p[1], p[2]))
            if e is not None: e["mgmt"] = ".".join(p[5:9])
    lldp = []
    for (lport, _r), e in nbr.items():
        lid, ldesc = s_(loc_id.get(lport)), s_(loc_desc.get(lport))
        lldp.append({"lport": lport, "lportId": lid, "lportDesc": ldesc,
                     "chId": mac_of(e.get("chId")) if e.get("chSub") == 4 else s_(e.get("chId")),
                     "pId": mac_of(e.get("pId")) if e.get("pSub") == 3 else s_(e.get("pId")),
                     "pDesc": s_(e.get("pDesc")), "sysName": s_(e.get("sysName")), "sysDesc": s_(e.get("sysDesc")),
                     "caps": e.get("caps") if isinstance(e.get("caps"), (bytes, bytearray)) else b"", "mgmt": e.get("mgmt", "")})
    d["lldp"] = lldp
    # CDP (Cisco)
    cdp_rows = W(CDP); cdp = {}
    for k, v in cdp_rows.items():
        col, ifi, di = k.split(".", 2)
        e = cdp.setdefault((ifi, di), {"ifIndex": ifi})
        if col == "4" and isinstance(v, bytes) and len(v) == 4: e["mgmt"] = ".".join(str(x) for x in v)
        elif col == "6": e["devId"] = s_(v)
        elif col == "7": e["port"] = s_(v)
        elif col == "8": e["platform"] = s_(v)
    d["cdp"] = list(cdp.values())
    # VLAN / PoE / LAG
    base_if = {k: str(v) for k, v in W(BASE_PORT_IF).items()}
    d["bridge_if"] = base_if
    d["pvid"] = {k: v for k, v in W(PVID).items()}
    eg, ut = W(VLAN_EGRESS), W(VLAN_UNTAGGED)
    tagged = {}
    for k, v in eg.items():
        vid = k.split(".")[-1]
        unt = bits_ports(ut.get(k, b""))
        for bp in bits_ports(v) - unt: tagged.setdefault(str(bp), []).append(vid)
    d["tagged"] = tagged
    d["poe"] = {k: v for k, v in W(POE_ADMIN).items()}
    d["lag"] = {k: str(v) for k, v in W(LAG_ATTACHED).items() if v}
    try: d["ifstack"] = [k for k, v in W(IF_STACK).items() if v in (1, None) or v == b"\x01"]
    except Exception: d["ifstack"] = []
    # FDB + ARP
    d["fdb"] = {}
    if want_fdb:
        q = W(QFDB_PORT)
        rows = {}
        for k, v in q.items():
            p = k.split(".")
            if len(p) >= 7: rows[":".join(f"{int(x):02X}" for x in p[-6:])] = str(v)
        if not rows:
            for k, v in W(FDB_PORT).items():
                p = k.split(".")
                if len(p) == 6: rows[":".join(f"{int(x):02X}" for x in p)] = str(v)
        d["fdb"] = rows
    arp = {}
    for k, v in W(ARP).items():
        p = k.split(".")
        if len(p) >= 5:
            m = mac_of(v)
            if m: arp[m] = ".".join(p[-4:])
    d["arp"] = arp
    return d

# ───────────────────────── build netmap project ─────────────────────────
_ids = 0
def nid(p):
    global _ids; _ids += 1; return f"{p}{_ids:05d}s"

def brand_of(dv):
    m = re.match(r"1\.3\.6\.1\.4\.1\.(\d+)", dv.get("sysOid", ""))
    b = ENTERPRISE.get(int(m.group(1)), "") if m else ""
    if not b:
        t = (dv.get("sysDescr", "") + " " + dv.get("mfg", "")).lower()
        for kw, name in DESCR_BRANDS:
            if kw in t: b = name; break
    return b

def caps_set(b):
    names = ["other", "repeater", "bridge", "wlanAP", "router", "telephone", "docsis", "station"]
    out = set()
    if isinstance(b, (bytes, bytearray)) and b:
        for i, n in enumerate(names):
            if b[0] & (0x80 >> i): out.add(n)
    return out

def classify(descr, brand, caps, model=""):
    t = (descr + " " + model).lower()
    if brand in FW_BRANDS or re.search(r"firewall|fortigate|pan-os|sonicos|utm", t): return "fw", None
    if "wlanAP" in caps or re.search(r"\baccess point\b|\bap\d|wireless|\bu6|\bu7|\beap\d|airengine|instant on ap|\bmr\d", t): return "ap", None
    if "telephone" in caps or re.search(r"\bsip-|ip phone|\bgxp|\bgrp\d|\bt\d\dw?\b", t): return "end", "IP Phone"
    if re.search(r"camera|ipc|network video|ds-2cd|\bip cam", t): return "end", "IP Cam"
    if re.search(r"nvr|ds-7\d", t): return "end", "NVR 錄影主機"
    if re.search(r"printer|laserjet|jetdirect|imageclass|imagerunner|bizhub|ecosys|apeos|mfc-|hl-l", t): return "end", "印表機"
    if re.search(r"synology|qnap|diskstation|nas\b", t): return "end", "NAS"
    if "router" in caps and "bridge" not in caps: return "router", None
    if re.search(r"\brouter\b|routeros|isr\d|vigor|edgeos|\ber\d{3}", t) and "bridge" not in caps: return "router", None
    if "bridge" in caps or re.search(r"switch|catalyst|nexus|procurve|aruba.*cx|ex\d{4}|\busw|\bsg\d|\bgs\d|dgs-|crs\d|s57\d\d|icx", t): return "sw", None
    if "station" in caps or re.search(r"windows|linux|darwin|macos", t): return "end", "伺服器" if re.search(r"server", t) else "PC 桌機"
    return "sw", None

PHYS_TYPES = {6, 62, 69, 117}
def is_phys(i):
    n = i["name"].lower()
    if re.match(r"^(vlan|vl\d|lo|loopback|null|tunnel|port-channel|po\d|bond|br|bridge|ae\d|lag|trk|mgmt0?$|cpu|stack|vif|wlan|ssid|dummy|docker|veth|virbr)", n): return False
    return i["type"] in PHYS_TYPES or i["type"] == 0

def port_kind(i):
    n = (i["name"] + " " + i["descr"]).lower()
    if re.search(r"sfp|te\d|tengig|twe|fo\d|hu\d|xe-|et-|xg|qsfp|fiber|10g|25g|40g|100g", n) or i["speed"] >= 10_000_000_000: return "sfp"
    return "rj45"

def port_label(name):
    """Gi1/0/7 → 7, Te1/1/1 → Te1, SFP2 → SFP2, port 12 → 12（埠圖示只放得下短標籤）"""
    n = short_if(name)
    if len(n) <= 6: return n
    m = re.match(r"^([A-Za-z]*)[^\d]*(?:[\d]+[/:.-])*(\d+)$", n)
    if not m: return n[:6]
    pre, num = m.group(1), m.group(2)
    if pre.lower() in ("", "gi", "fa", "eth", "ge", "port", "p", "lan", "e"): return num
    if pre.lower().startswith("internal"): return "LAN" + num
    return (pre[:4] + num)[:7]

def speed_txt(bps):
    if not bps: return ""
    g = bps / 1e9
    for v, t in ((100, "100G"), (40, "40G"), (25, "25G"), (10, "10G"), (5, "5G"), (2.5, "2.5G"), (1, "1G")):
        if g >= v * 0.99: return t
    return "100M" if bps >= 99e6 else ""

LAG_NAME_RE = re.compile(r"^(port-?channel|po\d|ae\d|bond|agg|aggregate|lag|trk|team|be\d|bundle-ether|eth-trunk|link-?agg)", re.I)

def lag_short(n):
    m = re.match(r"^(port-?channel|bundle-ether|eth-trunk|aggregate|link-?agg|bond|team|trk|ae|po|be|agg|lag)\s*-?(\d+)$", (n or "").strip(), re.I)
    if not m: return short_if(n or "")
    pre = {"port-channel": "Po", "portchannel": "Po", "bundle-ether": "BE", "eth-trunk": "Eth-Trunk", "aggregate": "agg", "linkagg": "agg", "link-agg": "agg"}.get(m.group(1).lower(), m.group(1))
    return f"{pre}{m.group(2)}"

def stack_lags(dv):
    """IEEE8023-LAG-MIB 沒有資料的設備（很多 Cisco、FortiGate、Linux bond）改從 IF-MIB 的介面堆疊表找聚合成員。"""
    out = {}
    ifs = dv.get("ifs", {})
    for k in dv.get("ifstack", []):
        hi, _, lo = str(k).partition(".")
        if hi in ("0", "") or lo in ("0", "") or hi not in ifs or lo not in ifs: continue
        H, L = ifs[hi], ifs[lo]
        if (H.get("type") == 161 or LAG_NAME_RE.match(H.get("name") or "")) and is_phys(L):
            out[lo] = lag_short(H["name"]) or f"Po{hi}"
    return out

def infer_lags(project, infra=("fw", "router", "sw", "hub", "ap")):
    """同一對設備之間有 2 條以上的線：
       一端已知是聚合、另一端不知道 → 另一端照對端的群組名稱標上（LACP 兩端都要設，才會通）；
       兩端都不知道 → 只標「可能是聚合」（也可能是 STP 備援線），讓使用者確認。回傳 (補上的埠數, 待確認的組數)。"""
    owner, port = {}, {}
    for d in project["devices"]:
        for p in d.get("ports", []): owner[p["id"]] = d; port[p["id"]] = p
    groups = {}
    for c in project["cables"]:
        a, b = owner.get(c["a"]), owner.get(c["b"])
        if not a or not b or a is b or a.get("type") not in infra or b.get("type") not in infra: continue
        if a["id"] > b["id"]: a, b, pa, pb = b, a, c["b"], c["a"]
        else: pa, pb = c["a"], c["b"]
        groups.setdefault((a["id"], b["id"]), []).append((port[pa], port[pb]))
    filled = hinted = 0; n = 0
    for (aid, bid), links in groups.items():
        if len(links) < 2: continue
        for x, y in links:   # 一端在聚合群組裡、另一端沒標：照對端補上
            for k, q in ((x, y), (y, x)):
                if k["lag"] and not q["lag"] and sum(1 for a2, b2 in links if (a2 if k is x else b2)["lag"] == k["lag"]) >= 2:
                    q["lag"] = k["lag"]; q["note"] = (q.get("note", "") + " 聚合群組依對端推測").strip(); filled += 1
        un = [(x, y) for x, y in links if not x["lag"] and not y["lag"]]
        if len(un) >= 2:
            n += 1; hinted += 1
            for x, y in un: x["lagHint"] = y["lagHint"] = f"H{n}"
    return filled, hinted

def build(devs, extra_lldp=True, fdb=True, max_macs_per_port=4):
    project = {"app": "netmap", "version": 3, "source": f"netmap-snmp {VERSION}", "savedAt": dt.datetime.now().isoformat(timespec="seconds"),
               "layout": "auto", "devices": [], "cables": [], "racks": [], "faults": []}
    D = project["devices"]; C = project["cables"]
    node = {}           # host → device dict
    portmap = {}        # (host, ifIndex) → port id
    used = set()        # port ids already cabled
    names = {}          # lower sysName / chassis MAC / IPs → host
    def add_cable(pa, pb, label=None, ctype="Cat6", speed=""):
        if not pa or not pb or pa == pb or pa in used or pb in used: return False
        used.add(pa); used.add(pb)
        C.append({"id": nid("c"), "a": pa, "b": pb, "label": label or f"S-{len(C) + 1:03d}", "type": ctype, "speed": speed,
                  "color": "#2C6FB7", "len": "", "dir": "none", "wps": []})
        return True
    # 1) scanned devices
    for dv in devs:
        brand = brand_of(dv); caps = caps_set(dv.get("caps"))
        typ, kind = classify(dv["sysDescr"], brand, caps, dv.get("model", ""))
        model = dv.get("model", "")
        if not model:
            m = re.search(r"(?:Cisco IOS.*?,\s*)?([A-Z]{1,6}[- ]?\d{2,5}[A-Z0-9\-+/]*)", dv["sysDescr"])
            model = m.group(1) if m and brand else ""
        ip = dv["host"].split(":")[0]
        dev = {"id": nid("d"), "type": typ, "name": dv["sysName"].split(".")[0][:40] or ip, "brand": brand, "model": model, "ip": ip, "mac": "",
               "gw": "", "loc": dv.get("sysLoc", ""), "note": f"SNMP 掃描 {dt.date.today().isoformat()}" + (f"・序號 {dv['serial']}" if dv.get("serial") else ""),
               "rack": "", "u": "", "uh": "", "x": 0, "y": 0, "ports": [], "snmp": {"host": dv["host"]}}
        if typ == "sw": dev["variant"] = "l3" if "router" in caps or len(dv.get("ips", {})) > 2 else "l2m"
        if typ == "end": dev["kind"] = kind or "其他"
        bif = {v: k for k, v in dv.get("bridge_if", {}).items()}  # ifIndex → bridge port
        lagname = {}
        for ifi, agg in dv.get("lag", {}).items():
            if agg != ifi and agg in dv["ifs"]: lagname[ifi] = lag_short(dv["ifs"][agg]["name"]) or f"Po{agg}"
        lagname.update({k: v for k, v in stack_lags(dv).items() if k not in lagname})
        phys = sorted([(k, v) for k, v in dv["ifs"].items() if is_phys(v)], key=lambda kv: int(kv[0]))
        poe_on = {k.split(".")[-1] for k, v in dv.get("poe", {}).items() if v == 1}
        for ifi, i in phys:
            bp = bif.get(ifi, ifi)
            pv = dv.get("pvid", {}).get(bp)
            tg = dv.get("tagged", {}).get(bp, [])
            p = {"id": nid("p"), "label": port_label(i["name"]) or ifi, "kind": port_kind(i), "poe": (bp in poe_on or ifi in poe_on),
                 "mode": "trunk" if tg else "access", "vlan": str(pv) if pv and not tg else "", "tagged": ",".join(sorted(set(tg), key=int)) if tg else "",
                 "lag": lagname.get(ifi, ""), "note": " ".join(x for x in [short_if(i["name"]) if port_label(i["name"]) != short_if(i["name"]) else "", i["alias"], "" if i["up"] else "（離線）", speed_txt(i["speed"])] if x)}
            if dv.get("pvid") and tg and pv: p["vlan"] = str(pv)
            p["ifIndex"] = int(ifi) if str(ifi).isdigit() else ifi
            dev["ports"].append(p); portmap[(dv["host"], ifi)] = p["id"]
        if not dev["ports"]:
            p = {"id": nid("p"), "label": "LAN", "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}
            dev["ports"].append(p)
        D.append(dev); node[dv["host"]] = dev
        names[dv["sysName"].lower()] = dv["host"]; names[dv["sysName"].split(".")[0].lower()] = dv["host"]
        for addr in dv.get("ips", {}): names[addr] = dv["host"]
        names[ip] = dv["host"]
        for i in dv["ifs"].values():
            if i["mac"]: names[i["mac"]] = dv["host"]
    def find_port(host, ident, desc=""):
        dv = next((x for x in devs if x["host"] == host), None)
        if not dv: return None
        cand = [ident, desc]
        for c in cand:
            if not c: continue
            cl = c.lower(); cs = short_if(c).lower()
            for ifi, i in dv["ifs"].items():
                if (host, ifi) not in portmap: continue
                if cl in (i["name"].lower(), i["descr"].lower(), i["alias"].lower(), short_if(i["name"]).lower()) or cs == short_if(i["name"]).lower() or (i["mac"] and cl == i["mac"].lower()):
                    return portmap[(host, ifi)]
            if c.isdigit() and (host, c) in portmap: return portmap[(host, c)]
        return None
    def local_port(dv, lport, lid, ldesc):
        if (dv["host"], lport) in portmap and (not lid or True):
            i = dv["ifs"].get(lport)
            if i and (not lid or lid.lower() in (i["name"].lower(), i["descr"].lower(), short_if(i["name"]).lower()) or lid.isdigit()): return portmap[(dv["host"], lport)]
        return find_port(dv["host"], lid, ldesc) or portmap.get((dv["host"], lport))
    ghosts = {}
    def ghost(name, desc, caps, mgmt, pname):
        key = (name or mgmt or desc).lower()
        if key in ghosts: g = ghosts[key]
        else:
            brand = ""
            for kw, b in DESCR_BRANDS:
                if kw in (desc or "").lower(): brand = b; break
            typ, kind = classify(desc or "", brand, caps)
            g = {"id": nid("d"), "type": typ, "name": (name or mgmt or "LLDP 鄰居")[:40], "brand": brand, "model": "", "ip": mgmt or "", "mac": "", "gw": "",
                 "loc": "", "note": "由 LLDP / CDP 鄰居資訊建立（未直接掃描）", "rack": "", "u": "", "uh": "", "x": 0, "y": 0, "ports": []}
            if typ == "sw": g["variant"] = "l2m"
            if typ == "end": g["kind"] = kind or "其他"
            ghosts[key] = g; D.append(g)
        lab = short_if(pname or "")[:12] or f"P{len(g['ports']) + 1}"
        p = next((x for x in g["ports"] if x["label"] == lab), None)
        if not p:
            p = {"id": nid("p"), "label": lab, "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}
            g["ports"].append(p)
        return p["id"]
    # 2) LLDP / CDP links
    linked_if = set()
    for dv in devs:
        for n in dv.get("lldp", []):
            lp = local_port(dv, n["lport"], n["lportId"], n["lportDesc"])
            if not lp: continue
            rh = names.get(n["sysName"].lower()) or names.get(n["sysName"].split(".")[0].lower()) or names.get(n["mgmt"]) or names.get(n["chId"].lower() if n["chId"] else "")
            rh = rh or names.get(n["chId"]) if n["chId"] else rh
            rp = find_port(rh, n["pId"], n["pDesc"]) if rh else None
            if not rp:
                if not extra_lldp or rh: continue
                rp = ghost(n["sysName"], n["sysDesc"], caps_set(n["caps"]), n["mgmt"], n["pDesc"] or n["pId"])
            ok = add_cable(lp, rp, speed=speed_txt(dv["ifs"].get(n["lport"], {}).get("speed", 0)))
            linked_if.add(lp)
            if not ok: linked_if.add(rp)
        for n in dv.get("cdp", []):
            lp = portmap.get((dv["host"], n["ifIndex"]))
            if not lp: continue
            dev_id = n.get("devId", "")
            rh = names.get(dev_id.lower()) or names.get(dev_id.split(".")[0].lower()) or names.get(n.get("mgmt", ""))
            rp = find_port(rh, n.get("port", "")) if rh else None
            if not rp:
                if not extra_lldp or rh: continue
                rp = ghost(dev_id.split("(")[0], n.get("platform", ""), set(), n.get("mgmt", ""), n.get("port", ""))
            add_cable(lp, rp, speed=speed_txt(dv["ifs"].get(n["ifIndex"], {}).get("speed", 0)))
            linked_if.add(lp)
    # 2b) 聚合（LACP）：一端已知就補另一端；兩端都不知道的平行線標成「可能是聚合」
    project["lagInfer"] = infer_lags(project)
    # 3) MAC table → end devices on access ports
    if fdb:
        arp = {}
        for dv in devs: arp.update(dv.get("arp", {}))
        known_macs = {m for m in names if re.fullmatch(r"[0-9A-F:]{17}", m)}
        for dv in devs:
            dev = node[dv["host"]]
            if dev["type"] not in ("sw", "hub"): continue
            bif = dv.get("bridge_if", {})
            per = {}
            for mac, bp in dv.get("fdb", {}).items():
                ifi = bif.get(bp, bp)
                pid = portmap.get((dv["host"], ifi))
                if pid: per.setdefault(pid, []).append(mac)
            for pid, ms in per.items():
                if pid in used: continue
                p = next(x for x in dev["ports"] if x["id"] == pid)
                if p["mode"] == "trunk" or p["lag"]: continue
                ms = [m for m in ms if m not in known_macs]
                if not ms: continue
                if len(ms) > max_macs_per_port:
                    hub = {"id": nid("d"), "type": "hub", "name": f"未管理交換器（{dev['name']} {p['label']}）", "brand": "", "model": "", "ip": "", "mac": "", "gw": "",
                           "loc": "", "note": f"這個埠學到 {len(ms)} 個 MAC，推測接了一台未管理交換器或 Hub", "rack": "", "u": "", "uh": "", "x": 0, "y": 0,
                           "ports": [{"id": nid("p"), "label": str(i + 1), "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""} for i in range(min(len(ms), 24) + 1)]}
                    D.append(hub); add_cable(pid, hub["ports"][0]["id"])
                    targets = list(zip(hub["ports"][1:], ms[:24]))
                else:
                    targets = [(None, m) for m in ms[:1]] if len(ms) == 1 else [(None, m) for m in ms]
                    if len(ms) > 1:
                        hub = {"id": nid("d"), "type": "hub", "name": f"小型交換器（{dev['name']} {p['label']}）", "brand": "", "model": "", "ip": "", "mac": "", "gw": "",
                               "loc": "", "note": f"這個埠學到 {len(ms)} 個 MAC", "rack": "", "u": "", "uh": "", "x": 0, "y": 0,
                               "ports": [{"id": nid("p"), "label": str(i + 1), "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""} for i in range(len(ms) + 1)]}
                        D.append(hub); add_cable(pid, hub["ports"][0]["id"])
                        targets = list(zip(hub["ports"][1:], ms))
                for hp, mac in targets:
                    ip = arp.get(mac, "")
                    e = {"id": nid("d"), "type": "end", "kind": "其他", "name": ip or mac, "brand": "", "model": "", "ip": ip, "mac": mac, "gw": "", "loc": "",
                         "note": "由 MAC 表推斷", "rack": "", "u": "", "uh": "", "x": 0, "y": 0,
                         "ports": [{"id": nid("p"), "label": "LAN", "kind": "rj45", "poe": False, "mode": "access", "vlan": p["vlan"], "tagged": "", "lag": "", "note": ""}]}
                    D.append(e); add_cable(hp["id"] if hp else pid, e["ports"][0]["id"])
    return project

# ───────────────────────── driver ─────────────────────────
def expand(targets):
    out = []
    for t in targets:
        t = t.strip()
        if not t: continue
        host, _, port = t.partition(":")
        try:
            net = ipaddress.ip_network(host, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
            out += [f"{h}:{port}" if port else str(h) for h in hosts]
        except ValueError:
            m = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", host)
            if m: out += [f"{m.group(1)}{i}" + (f":{port}" if port else "") for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            else: out.append(t)
    return list(dict.fromkeys(out))

def make_client(a, target, quick=False):
    host, _, port = target.partition(":")
    port = int(port or a.port)
    try: host = socket.gethostbyname(host)
    except OSError: pass
    to = min(a.timeout, 0.8) if quick else a.timeout
    if a.version == "3":
        return V3Client(host, a.user, a.auth_proto, a.auth_key, a.priv_proto, a.priv_key, port=port, timeout=to, retries=0 if quick else a.retries, context=a.context)
    return V2Client(host, a.community, a.version, port=port, timeout=to, retries=0 if quick else a.retries)

def probe(a, t):
    try:
        c = make_client(a, t, quick=True)
        try: return t if c.get([SYS["descr"]]) else None
        finally: c.close()
    except Exception:
        return None

# ───────────────────────── 網段探索（不需要 SNMP）＋ 診斷 ─────────────────────────
import subprocess
_NOWIN = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW：視窗版不要跳出黑色主控台

def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=_NOWIN)
        out = r.stdout or b""
        for enc in ("utf-8", "cp950", "mbcs" if os.name == "nt" else "latin-1"):
            try: return r.returncode, out.decode(enc)
            except (UnicodeDecodeError, LookupError): pass
        return r.returncode, out.decode("latin-1", "ignore")
    except Exception:
        return -1, ""

def ping_host(ip, timeout=0.8):
    """回傳 True 表示有收到這台的回覆（Windows 的 ping 對「目的地無法連線」也回 0，所以看 TTL=）。"""
    if os.name == "nt": code, out = _run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip], timeout + 3)
    else: code, out = _run(["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip], timeout + 3)
    return "ttl=" in out.lower()

PROBE_PORTS = [80, 443, 22, 23, 445, 139, 3389, 9100, 631, 554, 5060, 8080, 8443, 5000, 5001, 8009, 62078, 548]
def tcp_probe(ip, ports=PROBE_PORTS, timeout=0.35):
    """回傳 (alive, open_ports)。對方回 RST（連線被拒）也代表這台在線。"""
    alive, opened = False, []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        try:
            r = s.connect_ex((ip, p))
            if r == 0: alive = True; opened.append(p)
            elif r in (111, 10061): alive = True          # ECONNREFUSED / WSAECONNREFUSED
        except OSError: pass
        finally: s.close()
    return alive, opened

def parse_arp(text):
    """解析 Windows `arp -a`（中英文版）或 Linux /proc/net/arp、`ip neigh`。回傳 {ip: MAC}。"""
    out = {}
    for line in text.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\D[^\n]*?((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})", line)
        if not m: continue
        ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or mac.startswith("01:00:5E") or mac.startswith("33:33"): continue
        if ip.endswith(".255") or ip.startswith(("224.", "239.", "255.")): continue
        out[ip] = mac
    return out

def arp_table():
    if os.name == "nt": return parse_arp(_run(["arp", "-a"])[1])
    try: txt = open("/proc/net/arp").read()
    except OSError: txt = ""
    return parse_arp(txt + "\n" + _run(["ip", "neigh"])[1])

def parse_gateway(text):
    m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text, re.M) or re.search(r"default via (\d+\.\d+\.\d+\.\d+)", text)
    return m.group(1) if m else ""

def default_gateway():
    return parse_gateway(_run(["route", "print", "-4", "0.0.0.0"])[1] if os.name == "nt" else _run(["ip", "route", "show", "default"])[1])

def local_ipv4():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return ""

def local_subnet():
    ip = local_ipv4()
    return str(ipaddress.ip_network(ip + "/24", strict=False)) if ip else ""

_OUI = None
def oui_vendor(mac):
    """MAC 前 3 碼查廠牌（打包的 IEEE OUI 資料表；沒有資料表時回空字串）。"""
    global _OUI
    if not mac: return ""
    if int(mac[1], 16) & 2: return "隨機 MAC"
    if _OUI is None:
        _OUI = {}
        for d in ([getattr(sys, "_MEIPASS", "")] + [os.path.dirname(os.path.abspath(__file__))]):
            p = os.path.join(d, "oui.json.gz")
            if d and os.path.exists(p):
                import gzip
                try: _OUI = json.load(gzip.open(p, "rt", encoding="utf-8")); break
                except Exception: _OUI = {}
    return _OUI.get(mac.replace(":", "")[:6].upper(), "")

VENDOR_BRANDS = [("asustek", "ASUS"), ("asus", "ASUS"), ("tp-link", "TP-Link"), ("tplink", "TP-Link"), ("apple", "Apple"), ("samsung", "Samsung"),
                 ("hikvision", "Hikvision"), ("dahua", "Dahua"), ("vivotek", "VIVOTEK"), ("axis", "Axis"), ("synology", "Synology"), ("qnap", "QNAP"),
                 ("ubiquiti", "Ubiquiti"), ("cisco meraki", "Cisco Meraki"), ("cisco", "Cisco"), ("fortinet", "Fortinet"), ("zyxel", "Zyxel"),
                 ("d-link", "D-Link"), ("netgear", "Netgear"), ("mikrotik", "MikroTik"), ("routerboard", "MikroTik"), ("draytek", "DrayTek"),
                 ("huawei", "Huawei"), ("xiaomi", "Xiaomi"), ("google", "Google"), ("amazon", "Amazon"), ("sony", "Sony"), ("lg electronics", "LG"),
                 ("brother", "Brother"), ("seiko epson", "Epson"), ("epson", "Epson"), ("canon", "Canon"), ("ricoh", "Ricoh"), ("kyocera", "Kyocera"),
                 ("fuji", "FUJIFILM"), ("hewlett packard enterprise", "HPE"), ("hp inc", "HP"), ("hewlett", "HP"), ("dell", "Dell"), ("lenovo", "Lenovo"),
                 ("intel", "Intel"), ("realtek", "Realtek"), ("microsoft", "Microsoft"), ("raspberry", "Raspberry Pi"), ("yealink", "Yealink"),
                 ("grandstream", "Grandstream"), ("aruba", "Aruba (HPE)"), ("ruckus", "Ruckus"), ("espressif", "Espressif"), ("nintendo", "Nintendo")]
def brand_from_vendor(v):
    t = (v or "").lower()
    for k, b in VENDOR_BRANDS:
        if k in t: return b
    v = re.sub(r"[,.]?\s*(inc|co|ltd|corp|corporation|limited|gmbh|technologies|technology|electronics|computer)\b.*$", "", v or "", flags=re.I).strip(" ,.")
    return v[:24]

def guess_kind(ports, brand, vendor, is_gw, name=""):
    t = f"{brand} {vendor} {name}".lower()
    if is_gw: return "router", None
    if {9100, 631} & set(ports) or brand in ("Brother", "Epson", "Canon", "Ricoh", "Kyocera", "FUJIFILM"): return "end", "印表機"
    if 554 in ports or brand in ("Hikvision", "Dahua", "VIVOTEK", "Axis"): return "end", "IP Cam"
    if 5060 in ports or brand in ("Yealink", "Grandstream"): return "end", "IP Phone"
    if brand in ("Synology", "QNAP") or ({5000, 5001} <= set(ports)): return "end", "NAS"
    if 3389 in ports or {445, 139} & set(ports): return "end", "PC 桌機"
    if 62078 in ports or "iphone" in t or "ipad" in t: return "end", "其他"
    if brand in ("Ubiquiti", "Aruba (HPE)", "Ruckus") and 22 in ports: return "ap", None
    return "end", "其他"

def reverse_name(ip, timeout=1.5):
    res = [""]
    def f():
        try: res[0] = socket.gethostbyaddr(ip)[0]
        except Exception: pass
    th = __import__("threading").Thread(target=f, daemon=True); th.start(); th.join(timeout)
    n = res[0].split(".")[0] if res[0] and not re.fullmatch(r"[\d.]+", res[0]) else ""
    return n

def diagnose(target, log=print):
    """SNMP 沒回應時，判斷是「設備在線但沒開 SNMP」還是「整台連不到」。"""
    host = target.split(":")[0]
    try: ip = socket.gethostbyname(host)
    except OSError: log(f"  ？ {host}：找不到這個主機名稱"); return "noname"
    alive, opened = tcp_probe(ip, [80, 443, 8080, 8443, 22, 23], 0.6)
    pong = ping_host(ip)
    web = [p for p in opened if p in (80, 443, 8080, 8443)]
    if web:
        u = f"{'https' if web[0] in (443, 8443) else 'http'}://{ip}" + ("" if web[0] in (80, 443) else f":{web[0]}")
        log(f"  ● {ip}：設備在線（管理網頁 {', '.join(map(str, web))} 埠有回應），但 SNMP 沒有回應。")
        log(f"     → 多半是沒開 SNMP、community 不同，或設備只允許特定 IP 查詢。請登入 {u} 找 SNMP 設定。")
        return "online"
    if alive or pong:
        log(f"  ● {ip}：設備在線（{'ping' if pong else '連線'}有回應），但 SNMP 沒有回應。")
        log("     → 請確認設備有開 SNMP、community／帳密正確，並允許這台電腦的 IP 查詢。")
        return "online"
    log(f"  ✕ {ip}：連不到這台設備（ping 與常見埠都沒有回應）。請確認 IP 正確、這台電腦和設備在同一個網路。")
    return "down"

def discover(targets, log=print, progress=None, stop=lambda: False, link_gateway=True, workers=64):
    """不需要 SNMP：找出網段裡在線的設備，回傳可匯入的專案。"""
    targets = targets or [local_subnet()]
    hosts = [t.split(":")[0] for t in expand(targets)]
    me, gw = local_ipv4(), default_gateway()
    log(f"網段探索：{len(hosts)} 個位址（本機 {me or '?'}，預設閘道 {gw or '?'}）")
    found = {}
    def check(ip):
        if stop(): return ip, False, []
        alive, opened = tcp_probe(ip, [80, 443, 445, 22, 62078, 554, 9100], 0.3)
        if not alive: alive = ping_host(ip, 0.7)
        return ip, alive, opened
    done = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, alive, opened in ex.map(check, hosts):
            done += 1
            if progress and done % 4 == 0: progress(done, len(hosts), "probe")
            if alive: found[ip] = {"ports": opened}
    arp = arp_table()
    hostset = set(hosts)
    for ip in arp:
        if ip in hostset and ip not in found: found[ip] = {"ports": []}
    if me in hostset: found.setdefault(me, {"ports": []})
    log(f"在線設備：{len(found)} 台，讀取名稱與服務…")
    def detail(ip):
        alive, opened = tcp_probe(ip, PROBE_PORTS, 0.3)
        return ip, sorted(set(found[ip]["ports"]) | set(opened)), reverse_name(ip)
    infos = {}
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        for i, (ip, ports, name) in enumerate(ex.map(detail, list(found))):
            infos[ip] = (ports, name)
            if progress: progress(i + 1, len(found), "detail")
    project = {"app": "netmap", "version": 3, "source": f"netmap-discover {VERSION}", "savedAt": dt.datetime.now().isoformat(timespec="seconds"),
               "layout": "auto", "devices": [], "cables": [], "racks": [], "faults": []}
    D = project["devices"]; gwdev = None
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        ports, name = infos.get(ip, ([], ""))
        mac = arp.get(ip, "")
        vendor = oui_vendor(mac); brand = brand_from_vendor(vendor) if vendor != "隨機 MAC" else ""
        typ, kind = guess_kind(ports, brand, vendor, ip == gw, name)
        svc = {80: "網頁", 443: "HTTPS", 22: "SSH", 23: "Telnet", 445: "檔案分享", 3389: "遠端桌面", 9100: "列印", 631: "列印", 554: "影像串流",
               5060: "SIP", 5000: "NAS", 5001: "NAS", 8009: "投放", 62078: "iOS", 548: "AFP", 8080: "網頁", 8443: "HTTPS"}
        label = name or ("這台電腦" if ip == me else ("路由器" if ip == gw else (f"{kind} {ip}" if kind and kind != "其他" else (f"{brand} {ip}" if brand else ip))))
        d = {"id": nid("d"), "type": typ, "name": label[:40], "brand": brand if brand in ("ASUS", "TP-Link", "Apple", "Hikvision", "Dahua", "VIVOTEK", "Axis", "Synology", "QNAP",
             "Ubiquiti", "Cisco", "Fortinet", "Zyxel", "D-Link", "Netgear", "MikroTik", "DrayTek", "Huawei", "Brother", "Epson", "Canon", "Ricoh", "Kyocera",
             "FUJIFILM", "HP", "Dell", "Lenovo", "Samsung", "Yealink", "Grandstream", "Aruba (HPE)", "Ruckus") else "", "model": "",
             "ip": ip, "mac": mac, "gw": gw if ip != gw else "", "loc": "",
             "note": " · ".join(x for x in [("MAC 廠商：" + vendor) if vendor else "", "開放：" + "、".join(dict.fromkeys(svc[p] for p in ports if p in svc)) if ports else "",
                                            "這台電腦" if ip == me and name else "", "由網段探索建立，接法請自行確認"] if x),
             "rack": "", "u": "", "uh": "", "x": 0, "y": 0, "ports": []}
        d["monitor"] = False   # 網段探索找到的設備多半沒有 SNMP，預設不讓監控服務去輪詢
        if typ == "router":
            d["ports"] = [{"id": nid("p"), "label": "WAN", "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}]
            gwdev = d
        elif typ == "ap":
            d["ports"] = [{"id": nid("p"), "label": "ETH1", "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}]
        else:
            d["kind"] = kind or "其他"
            d["ports"] = [{"id": nid("p"), "label": "LAN", "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}]
        D.append(d)
    if link_gateway and gwdev:
        others = [d for d in D if d is not gwdev]
        for i, d in enumerate(others):
            p = {"id": nid("p"), "label": f"LAN{i + 1}", "kind": "rj45", "poe": False, "mode": "access", "vlan": "", "tagged": "", "lag": "", "note": ""}
            gwdev["ports"].append(p)
            project["cables"].append({"id": nid("c"), "a": p["id"], "b": d["ports"][0]["id"], "label": f"N-{i + 1:03d}", "type": "Cat6", "speed": "",
                                      "color": "#7D8794", "len": "", "dir": "none", "wps": []})
    if progress: progress(1, 1, "done")
    log(f"完成：{len(D)} 台設備" + ("，已先接到路由器（實際是有線還是 Wi‑Fi、接在哪個埠請自行調整）" if link_gateway and gwdev else ""))
    return project

DEFAULTS = dict(community="public", version="2c", user=None, auth_proto="SHA", auth_key=None, priv_proto="AES", priv_key=None, context="",
                port=161, timeout=2.0, retries=1, workers=48, max_devices=300, no_follow=False, no_fdb=False, no_neighbors=False)

def opts(**kw):
    o = argparse.Namespace(**DEFAULTS); o.__dict__.update({k: v for k, v in kw.items() if v is not None}); return o

def run_scan(a, targets, log=print, progress=None, stop=lambda: False, on_device=None):
    """掃描並建立專案。log(text)、progress(done, total, phase)、stop() 回傳 True 即中止。回傳 (project, devs, failed)。"""
    targets = expand(targets)
    log(f"探測 {len(targets)} 個位址…")
    alive, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=max(1, min(a.workers, len(targets) or 1))) as ex:
        futs = {ex.submit(probe, a, t): t for t in targets}
        for fu in cf.as_completed(futs):
            done += 1
            if fu.result(): alive.append(fu.result())
            if progress: progress(done, len(targets), "probe")
            if stop():
                for x in futs: x.cancel()
                break
    alive.sort(key=lambda t: [int(x) if x.isdigit() else 0 for x in re.split(r"[.:]", t)])
    log(f"有回應的設備：{len(alive)} 台")
    if not alive and not stop():
        if len(targets) <= 8:
            log("\n檢查為什麼沒有回應…")
            for t in targets: diagnose(t, log)
        else:
            log("\n整個範圍都沒有設備回應 SNMP。家用路由器、電腦、手機通常不支援 SNMP；只想列出在線的設備，可改用「網段探索」（--discover）。")
    seen, queue, devs, failed = set(), list(alive), [], []
    while queue and len(devs) < a.max_devices and not stop():
        t = queue.pop(0)
        host = t.split(":")[0]
        if host in seen: continue
        seen.add(host)
        if progress: progress(len(devs), len(devs) + len(queue) + 1, "collect")
        try:
            c = make_client(a, t)
            try:
                dv = collect(c, t, want_fdb=not a.no_fdb)
            finally:
                c.close()
        except Exception as e:
            failed.append((t, str(e))); log(f"  ✕ {t}：" + ("沒有回應（可能沒開 SNMP，或 community／帳密不同）" if "timeout" in str(e) else str(e))); continue
        devs.append(dv)
        if on_device: on_device(dv)
        for x in dv.get("ips", {}): seen.add(x)
        log(f"  ✓ {t:<21} {dv['sysName'][:28]:<28} 埠 {sum(1 for i in dv['ifs'].values() if is_phys(i)):>3}  LLDP {len(dv['lldp']):>2}  CDP {len(dv['cdp']):>2}  MAC {len(dv['fdb']):>4}")
        if not a.no_follow:
            port = t.partition(":")[2]
            for n in dv["lldp"] + dv["cdp"]:
                m = n.get("mgmt")
                if m and m not in seen: queue.append(m + (f":{port}" if port else ""))
    if progress: progress(1, 1, "done")
    proj = build(devs, extra_lldp=not a.no_neighbors, fdb=not a.no_fdb) if devs else None
    if proj:
        proj["snmpAuth"] = {"version": a.version, "port": a.port}
    return proj, devs, failed

def main(argv=None):
    ap = argparse.ArgumentParser(prog="netmap-snmp", description="用 SNMP 掃描網路設備，輸出 RackTrace 可匯入的 JSON。")
    ap.add_argument("targets", nargs="*", help="IP、網段或範圍，例如 192.168.1.1  192.168.1.0/24  10.0.0.1-50  host:1161")
    ap.add_argument("-c", "--community", default="public", help="SNMP community（v1/v2c，預設 public）")
    ap.add_argument("-v", "--version", default="2c", choices=["1", "2c", "3"], help="SNMP 版本（預設 2c）")
    ap.add_argument("-u", "--user", help="SNMPv3 使用者")
    ap.add_argument("-a", "--auth-proto", default="SHA", choices=["MD5", "SHA", "SHA256", "SHA512"])
    ap.add_argument("-A", "--auth-key", help="SNMPv3 認證密碼")
    ap.add_argument("-x", "--priv-proto", default="AES", choices=["DES", "AES", "AES256"])
    ap.add_argument("-X", "--priv-key", help="SNMPv3 加密密碼")
    ap.add_argument("-n", "--context", default="", help="SNMPv3 context name（多數設備留空）")
    ap.add_argument("-p", "--port", type=int, default=161)
    ap.add_argument("-t", "--timeout", type=float, default=2.0)
    ap.add_argument("-r", "--retries", type=int, default=1)
    ap.add_argument("-w", "--workers", type=int, default=48, help="同時探測的數量（掃網段用）")
    ap.add_argument("-o", "--output", help="輸出檔名（預設 netmap-scan-日期時間.json）")
    ap.add_argument("--no-follow", action="store_true", help="不要自動掃描 LLDP/CDP 鄰居的管理 IP")
    ap.add_argument("--max-devices", type=int, default=300)
    ap.add_argument("--no-fdb", action="store_true", help="不讀 MAC 表（不推斷終端設備）")
    ap.add_argument("--no-neighbors", action="store_true", help="不為沒掃到的 LLDP/CDP 鄰居建立設備")
    ap.add_argument("--raw", help="另存原始資料（除錯用）")
    ap.add_argument("--discover", action="store_true", help="網段探索：不需要 SNMP，用 ping／ARP 列出在線設備（不填目標＝本機網段）")
    ap.add_argument("--no-link", action="store_true", help="網段探索時不要把設備先接到預設閘道")
    ap.add_argument("--version-info", action="version", version=f"netmap-snmp {VERSION}")
    a = ap.parse_args(argv)
    interactive = not a.targets and not a.discover
    if interactive:
        print(f"netmap-snmp {VERSION}  —  RackTrace SNMP 掃描\n")
        print("輸入要掃描的設備 IP 或網段（可多個，用空白分隔），例如：192.168.1.1 192.168.1.0/24")
        a.targets = input("掃描目標：").split()
        if not a.targets: print("沒有輸入目標。"); return 1
        v = input("SNMP 版本 [2c]（輸入 3 使用 SNMPv3）：").strip() or "2c"
        a.version = v if v in ("1", "2c", "3") else "2c"
        if a.version == "3":
            a.user = input("SNMPv3 使用者：").strip()
            a.auth_key = input("認證密碼（沒有就留空）：").strip() or None
            if a.auth_key: a.auth_proto = (input("認證演算法 [SHA]（MD5/SHA/SHA256/SHA512）：").strip().upper() or "SHA")
            a.priv_key = input("加密密碼（沒有就留空）：").strip() or None
            if a.priv_key: a.priv_proto = (input("加密演算法 [AES]（DES/AES/AES256）：").strip().upper() or "AES")
        else:
            a.community = input("Community [public]：").strip() or "public"
    if a.version == "3" and not a.user: print("SNMPv3 需要 -u 使用者"); return 2
    t0 = time.time()
    print()
    if a.discover:
        proj = discover(a.targets, link_gateway=not a.no_link)
        out = a.output or f"netmap-discover-{dt.datetime.now():%Y%m%d-%H%M}.json"
        with open(out, "w", encoding="utf-8") as f: json.dump(proj, f, ensure_ascii=False, indent=1)
        print(f"→ {os.path.abspath(out)}\n下一步：打開 {APP_URL} ，選「匯入 ▸ 開啟專案檔」。"); return 0
    proj, devs, failed = run_scan(a, a.targets)
    if not proj:
        print("\n沒有收集到任何設備。請確認：IP 正確、設備已開啟 SNMP、community / 帳密正確、防火牆允許 UDP 161。")
        return 3
    out = a.output or f"netmap-scan-{dt.datetime.now():%Y%m%d-%H%M}.json"
    with open(out, "w", encoding="utf-8") as f: json.dump(proj, f, ensure_ascii=False, indent=1)
    if a.raw:
        with open(a.raw, "w", encoding="utf-8") as f:
            json.dump(devs, f, ensure_ascii=False, indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o))
    nd, nc = len(proj["devices"]), len(proj["cables"])
    print(f"\n完成（{time.time() - t0:.1f} 秒）：{nd} 台設備、{nc} 條線 → {os.path.abspath(out)}")
    lf, lh = proj.get("lagInfer") or (0, 0)
    if lf or lh: print(f"聚合（LACP）：依對端補上 {lf} 個埠" + (f"；{lh} 組平行線可能是聚合（也可能是備援線），請在網頁點那條線確認" if lh else "") + "。")
    print(f"下一步：打開 {APP_URL} ，在首頁選「匯入 ▸ JSON 專案檔」，選這個檔案。")
    if failed: print(f"有 {len(failed)} 台沒讀到完整資料，可加上 -t 5 延長逾時後重試。")
    if interactive and os.name == "nt":
        try: os.startfile(os.path.dirname(os.path.abspath(out)))
        except Exception: pass
    return 0

if __name__ == "__main__":
    code = 0
    try: code = main()
    except KeyboardInterrupt: print("\n已取消。"); code = 130
    if len(sys.argv) == 1 and os.name == "nt" and getattr(sys, "frozen", False):
        try: input("\n按 Enter 關閉視窗…")
        except Exception: pass
    sys.exit(code)
