# -*- coding: utf-8 -*-
"""
netmap 圖面比對（自動對帳）：拿設備實際的 LLDP／CDP 鄰居與 MAC 表，和圖上的線比對。

  audit(project, collected)  collected = {設備id: netmap_snmp.collect() 的結果}
    → (findings, verified)
       findings: [{key, kind, level, dev, port, cable, text, fix}]
       verified: {線id: "LLDP" | "CDP" | "MAC 表"}   ← 實際資料確認過的線（沿路經過配線架的每一段都算）

  kind：
    peer     圖上接的設備和實際不同（接錯線，或改線沒更新）
    port     接的設備對，但對端埠號不同
    missing  實際有連線（LLDP／CDP），圖上沒畫
    unknown  實際接著一台圖上沒有的設備
    moved    終端設備的 MAC 出現在別的埠（改線沒更新）
    endmiss  終端設備圖上沒接線，但 MAC 表看得到它接在哪
    down     圖上兩台網路設備之間有線，但那個埠目前沒有連線
"""
import re
import netmap_snmp as ns

PASS_TYPES = {"patch", "seat"}
INFRA = {"fw", "router", "sw", "hub", "ap"}


def norm_mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", str(m or "")).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


class Map:
    """圖上的索引：埠 → 設備、埠 → 線，沿線穿過配線架走到底。"""
    def __init__(s, project):
        s.p = project
        s.owner, s.port, s.cab = {}, {}, {}
        for d in project.get("devices", []):
            for p in d.get("ports", []): s.owner[p["id"]] = d; s.port[p["id"]] = p
        for c in project.get("cables", []):
            if c.get("a") in s.owner and c.get("b") in s.owner: s.cab[c["a"]] = c; s.cab[c["b"]] = c
        s.byid = {d["id"]: d for d in project.get("devices", [])}

    def run(s, pid):
        """從 pid 出發沿線走到底：回傳 (最遠的埠, [經過的線], 最後一條線)；沒接線回傳 (None, [], None)。"""
        cur, seen, cables = pid, {pid}, []
        for _ in range(64):
            c = s.cab.get(cur)
            if not c or c in cables: break
            cables.append(c)
            nx = c["b"] if c["a"] == cur else c["a"]
            if nx in seen: break
            seen.add(nx); cur = nx
            d, p = s.owner[nx], s.port[nx]
            if d.get("type") in PASS_TYPES and p.get("pair") and p["pair"] not in seen and s.cab.get(p["pair"]):
                seen.add(p["pair"]); cur = p["pair"]; continue
            break
        if not cables: return None, [], None
        return cur, cables, cables[-1]

    def pname(s, pid):
        d, p = s.owner.get(pid), s.port.get(pid)
        return f"{d.get('name', '')} 埠 {p.get('label', '')}" if d and p else "?"


def _key(*parts): return "|".join(str(x) for x in parts)


def audit(project, collected, mac_access_max=3):
    M = Map(project)
    findings, verified = {}, {}
    def F(key, **kw):
        kw.setdefault("level", "warn"); kw["key"] = key; findings.setdefault(key, kw)
    def ok(cables, how):
        for c in cables: verified.setdefault(c["id"], how)

    # 名稱、IP、MAC → 圖上的設備
    names = {}
    def put(k, d):
        if k: names.setdefault(str(k).lower(), d)
    for d in project.get("devices", []):
        put(d.get("name"), d); put(str(d.get("name", "")).split(".")[0], d); put(d.get("ip"), d)
        put((d.get("snmp") or {}).get("host"), d); put(norm_mac(d.get("mac")), d)
    for did, dv in collected.items():
        d = M.byid.get(did)
        if not d: continue
        put(dv.get("sysName"), d); put(str(dv.get("sysName", "")).split(".")[0], d)
        for a in (dv.get("ips") or {}): put(a, d)
        for i in dv.get("ifs", {}).values(): put(norm_mac(i.get("mac")), d)

    # 每台有實際資料的設備：ifIndex → 圖上的埠
    def ifmap(d, dv):
        out = {}; bylab = {}
        for p in d.get("ports", []):
            if p.get("ifIndex") not in (None, ""): out[str(p["ifIndex"])] = p["id"]
            bylab.setdefault(str(p.get("label", "")).lower(), p["id"])
            first = (p.get("note") or "").split(" ")[0].lower()
            if first: bylab.setdefault(first, p["id"])
        for ifi, i in dv.get("ifs", {}).items():
            if ifi in out: continue
            for k in (ns.port_label(i["name"]).lower(), ns.short_if(i["name"]).lower(), i["name"].lower()):
                if k in bylab: out[ifi] = bylab[k]; break
        return out
    IFM = {did: ifmap(M.byid[did], dv) for did, dv in collected.items() if did in M.byid}

    def find_port(d, ident, desc=""):
        """對端設備上的埠：有實際資料就用介面名稱對 ifIndex，沒有就比對圖上的埠名稱。"""
        dv = collected.get(d["id"])
        for c in (ident, desc):
            if not c: continue
            cl, cs = c.lower(), ns.short_if(c).lower()
            if dv:
                for ifi, i in dv.get("ifs", {}).items():
                    if cl in (i["name"].lower(), i["descr"].lower(), i["alias"].lower(), ns.short_if(i["name"]).lower()) or cs == ns.short_if(i["name"]).lower() or (i.get("mac") and cl == i["mac"].lower()):
                        pid = IFM.get(d["id"], {}).get(ifi)
                        if pid: return pid
            for p in d.get("ports", []):
                lab = str(p.get("label", "")).lower()
                if lab and (lab == cl or lab == cs or lab == ns.port_label(c).lower() or (p.get("note") or "").split(" ")[0].lower() in (cl, cs)): return p["id"]
        return None

    # ── LLDP／CDP ──
    seen_pairs = set(); nbr_ports = {}
    for did, dv in collected.items():
        d = M.byid.get(did)
        if not d: continue
        im = IFM[did]
        nb = []
        for n in dv.get("lldp", []):
            lp = im.get(str(n["lport"]))
            if not lp:
                for ifi, i in dv.get("ifs", {}).items():
                    if n.get("lportId") and n["lportId"].lower() in (i["name"].lower(), ns.short_if(i["name"]).lower()): lp = im.get(ifi); break
            nb.append(("LLDP", lp, n.get("sysName", ""), n.get("mgmt", ""), n.get("chId", ""), n.get("pId", ""), n.get("pDesc", ""), n.get("sysDesc", "")))
        for n in dv.get("cdp", []):
            nb.append(("CDP", im.get(str(n.get("ifIndex"))), (n.get("devId") or "").split("(")[0], n.get("mgmt", ""), "", n.get("port", ""), "", n.get("platform", "")))
        for how, lp, sysn, mgmt, chid, pid_, pdesc, sdesc in nb:
            if not lp: continue
            nbr_ports[lp] = True
            R = names.get(sysn.lower()) or names.get(sysn.split(".")[0].lower()) or names.get(mgmt) or names.get(norm_mac(chid)) if (sysn or mgmt or chid) else None
            if R is d: continue
            far, cables, last = M.run(lp)
            fd = M.owner.get(far) if far else None
            rname = sysn or mgmt or chid or "未知設備"
            rport = pdesc or pid_
            if R is None:
                if fd is None:
                    F(_key("unknown", lp, rname.lower()), kind="unknown", dev=d["id"], port=lp, level="info",
                      text=f"{M.pname(lp)} 實際接著「{rname}」{('（' + rport + '）') if rport else ''}，這台不在圖上，圖上也沒畫線", how=how)
                elif fd.get("type") not in PASS_TYPES:
                    F(_key("peer", lp, rname.lower()), kind="peer", dev=d["id"], port=lp, cable=last["id"], level="bad",
                      text=f"{M.pname(lp)}：圖上接到 {M.pname(far)}，但 {how} 看到的是「{rname}」{('（' + rport + '）') if rport else ''}", how=how)
                continue
            rp = find_port(R, pid_, pdesc)
            pair = tuple(sorted([lp, rp or R["id"]]))
            if pair in seen_pairs: continue
            seen_pairs.add(pair)
            if fd is None:
                fix = None
                if rp and not M.cab.get(rp): fix = {"op": "add", "a": lp, "b": rp}
                F(_key("missing", *pair), kind="missing", dev=d["id"], port=lp, level="warn", fix=fix,
                  text=f"{M.pname(lp)} 實際接到 {M.pname(rp) if rp else R.get('name', '') + (' ' + rport if rport else '')}（{how}），圖上沒有畫這條線", how=how)
            elif fd["id"] == R["id"]:
                if rp and far != rp:
                    fix = {"op": "move", "cable": last["id"], "from": far, "to": rp} if not M.cab.get(rp) else None
                    F(_key("port", lp, far, rp), kind="port", dev=d["id"], port=lp, cable=last["id"], level="warn", fix=fix,
                      text=f"{M.pname(lp)}：圖上接 {M.pname(far)}，實際是 {M.pname(rp)}（{how}）", how=how)
                else:
                    ok(cables, how)
            elif fd.get("type") not in PASS_TYPES:
                F(_key("peer", lp, R["id"]), kind="peer", dev=d["id"], port=lp, cable=last["id"], level="bad",
                  text=f"{M.pname(lp)}：圖上接到 {M.pname(far)}，實際接的是 {M.pname(rp) if rp else R.get('name', '')}（{how}）", how=how)

    # ── MAC 表：終端設備實際接在哪個埠 ──
    where = {}   # mac → [(switch 設備, 圖上的埠 id)]
    for did, dv in collected.items():
        d = M.byid.get(did)
        if not d or d.get("type") not in ("sw", "hub", "ap", "router", "fw"): continue
        bif = dv.get("bridge_if", {}); im = IFM[did]
        per = {}
        for mac, bp in (dv.get("fdb") or {}).items(): per.setdefault(bif.get(bp, bp), []).append(mac)
        for ifi, macs in per.items():
            pid = im.get(str(ifi))
            if not pid or len(macs) > mac_access_max or pid in nbr_ports: continue     # 上聯埠（很多 MAC 或有 LLDP 鄰居）不算
            far, _c, _l = M.run(pid)
            if far and M.owner[far].get("type") in INFRA: continue                    # 圖上接到另一台網路設備的埠也不算
            for m in macs: where.setdefault(norm_mac(m), []).append((d, pid))
    for E in project.get("devices", []):
        if E.get("type") in INFRA or E.get("type") in PASS_TYPES: continue
        mac = norm_mac(E.get("mac"))
        obs = where.get(mac) if mac else None
        if not obs or len(obs) != 1: continue
        sw, op = obs[0]
        mine = [p["id"] for p in E.get("ports", []) if M.cab.get(p["id"])]
        if not mine:
            free = [p["id"] for p in E.get("ports", [])]
            F(_key("endmiss", E["id"], op), kind="endmiss", dev=E["id"], port=op, level="info",
              fix={"op": "add", "a": free[0], "b": op} if free and not M.cab.get(op) else None,
              text=f"{E.get('name', '')} 圖上沒有接線，MAC 表看到它接在 {M.pname(op)}", how="MAC 表")
            continue
        far, cables, last = M.run(mine[0])
        if not far: continue
        fd = M.owner[far]
        if far == op: ok(cables, "MAC 表"); continue
        if fd["id"] not in collected: continue          # 圖上那一端沒有實際資料（傻瓜 Switch 等），無法判斷
        fix = {"op": "move", "cable": last["id"], "from": far, "to": op} if not M.cab.get(op) else None
        F(_key("moved", E["id"], op), kind="moved", dev=E["id"], port=mine[0], cable=last["id"], level="warn", fix=fix,
          text=f"{E.get('name', '')}：圖上接在 {M.pname(far)}，但 MAC 表顯示它在 {M.pname(op)}（改線沒更新圖？）", how="MAC 表")

    # ── 圖上有線、埠卻沒有連線（只看網路設備之間的線） ──
    for did, dv in collected.items():
        d = M.byid.get(did)
        if not d: continue
        for ifi, pid in IFM[did].items():
            i = dv.get("ifs", {}).get(ifi)
            if not i or i.get("up") or not M.cab.get(pid): continue
            far, cables, last = M.run(pid)
            if not far: continue
            fd = M.owner[far]
            if fd.get("type") in INFRA and fd["id"] != did:
                F(_key("down", pid), kind="down", dev=did, port=pid, cable=last["id"], level="info",
                  text=f"{M.pname(pid)} 圖上接到 {M.pname(far)}，但這個埠目前沒有連線（線拔了、對端關機，或圖面過時）", how="SNMP")

    # 有問題的線不算「已確認」
    for f in findings.values():
        if f.get("cable"): verified.pop(f["cable"], None)
    return list(findings.values()), verified
