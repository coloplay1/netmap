"""各廠牌設定教學：怎麼開 SNMP（給掃描與監控）、怎麼開流量匯出（NetFlow／IPFIX／sFlow，給「誰在用」）。

文字裡的 {IP} 是跑 netmap.exe 那台電腦的 IP，{NF} 是 NetFlow／IPFIX 埠（預設 2055），{SF} 是 sFlow 埠（預設 6343），
{COMM} 是建議的唯讀 community 名稱。選單位置依韌體版本可能略有不同。
這個檔案同時是網頁版與使用手冊的資料來源（建置時轉成 JSON）。
"""

VENDORS = [
    {"id": "sonicwall", "name": "SonicWall", "kind": "防火牆（SonicOS 7）", "match": ["sonicwall"],
     "snmp": ["Device ▸ Settings ▸ SNMP：勾選 Enable SNMP，在 View 設定唯讀 community「{COMM}」（或建立 SNMPv3 使用者）。",
              "Network ▸ System ▸ Interfaces：編輯 LAN 介面（例如 X0），在 Management 勾選 SNMP，允許從內網查詢。",
              "存取規則若有限制，允許 {IP} 連到防火牆的 UDP 161。"],
     "flow": "IPFIX（建議）／NetFlow v9／v5",
     "flow_steps": ["Device ▸ AppFlow ▸ Flow Reporting ▸ Settings：Report Connections 選 All（或 Interface-based 只報指定介面）。",
                    "External Collector 分頁：勾選「Send Flows and Real-Time Data To External Collector」（可能需要重新開機）。",
                    "External Flow Reporting Format 選 IPFIX，External Collector's IP 填 {IP}，Port 填 {NF}。",
                    "按 Generate ALL Templates 產生範本，再按 Accept。"],
     "doc": "https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-appflow_device/Content/appflow-d-flow-reporting-user-config-netflow-v10.htm"},

    {"id": "fortinet", "name": "Fortinet FortiGate", "kind": "防火牆（FortiOS）", "match": ["fortinet", "fortigate", "fortiswitch"],
     "snmp": ["System ▸ SNMP：開啟 SNMP Agent，新增 SNMP v1/v2c community「{COMM}」，Hosts 加入 {IP}，只勾 Accept queries（或用 SNMPv3）。",
              "Network ▸ Interfaces：編輯 LAN 介面，Administrative Access 勾選 SNMP。"],
     "snmp_cli": "config system snmp sysinfo\n    set status enable\nend\nconfig system snmp community\n    edit 1\n        set name \"{COMM}\"\n        config hosts\n            edit 1\n                set ip {IP} 255.255.255.255\n            next\n        end\n        set trap-v1-status disable\n        set trap-v2c-status disable\n    next\nend",
     "flow": "NetFlow v9（一筆含雙向流量）",
     "flow_steps": ["只能用 CLI 設定（FortiOS 7.4.2 以後可設多個收集器）。", "在 LAN 介面開啟取樣（netflow-sampler）。舊版 FortiOS 是 config system netflow 底下直接 set collector-ip。"],
     "flow_cli": "config system netflow\n    config collectors\n        edit 1\n            set collector-ip {IP}\n            set collector-port {NF}\n        next\n    end\nend\nconfig system interface\n    edit \"internal\"\n        set netflow-sampler both\n    next\nend",
     "doc": "https://docs.fortinet.com/document/fortigate/7.4.0/new-features/840728"},

    {"id": "cisco", "name": "Cisco Catalyst／IOS", "kind": "交換器、路由器（IOS／IOS-XE）", "match": ["cisco", "catalyst"],
     "snmp": ["用 ACL 限定只有 {IP} 能查詢，並開啟 LLDP（CDP 預設已開）。"],
     "snmp_cli": "ip access-list standard NETMAP\n permit host {IP}\nsnmp-server community {COMM} RO NETMAP\nlldp run",
     "flow": "Flexible NetFlow v9（路由器、Catalyst 9300／9400 等；部分入門款交換器不支援）",
     "flow_steps": ["在連接內網的介面套用 flow monitor（ingress）。"],
     "flow_cli": "flow exporter NETMAP\n destination {IP}\n transport udp {NF}\n export-protocol netflow-v9\nflow monitor NETMAP-MON\n exporter NETMAP\n record netflow ipv4 original-input\ninterface GigabitEthernet0/1\n ip flow monitor NETMAP-MON input"},

    {"id": "meraki", "name": "Cisco Meraki", "kind": "MX 防火牆、MS 交換器", "match": ["meraki"],
     "snmp": ["Organization ▸ Settings：開啟 SNMP（這是雲端的 SNMP，netmap 讀不到埠流量）。",
              "要讓 netmap 直接讀設備：Network-wide ▸ General ▸ Reporting 開啟 SNMP，設定 community「{COMM}」，並允許 {IP}。"],
     "flow": "NetFlow v9（MX）",
     "flow_steps": ["Network-wide ▸ Configure ▸ General ▸ Reporting：NetFlow traffic reporting 選 Enabled。",
                    "NetFlow collector IP 填 {IP}，port 填 {NF}，儲存。",
                    "MX 只匯出經過路由或 NAT 的流量，同一個 VLAN 裡互傳的流量不會出現。"],
     "doc": "https://documentation.meraki.com/MX/Monitoring_and_Reporting/NetFlow_Overview"},

    {"id": "mikrotik", "name": "MikroTik RouterOS", "kind": "路由器、交換器", "match": ["mikrotik", "routerboard"],
     "snmp": ["IP ▸ SNMP：Enabled 打勾；Communities 改成「{COMM}」，Addresses 填 {IP}/32，只開 Read Access。"],
     "snmp_cli": "/snmp set enabled=yes\n/snmp community set [find default=yes] name={COMM} addresses={IP}/32 read-access=yes write-access=no",
     "flow": "NetFlow v9／IPFIX（Traffic Flow）",
     "flow_steps": ["IP ▸ Traffic Flow：Enabled 打勾，Interfaces 選 all。", "Targets 新增：Dst. Address {IP}、Port {NF}、Version 9（或 IPFIX）。"],
     "flow_cli": "/ip traffic-flow set enabled=yes interfaces=all\n/ip traffic-flow target add dst-address={IP} port={NF} version=9",
     "doc": "https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow/"},

    {"id": "ubiquiti", "name": "Ubiquiti UniFi", "kind": "閘道器、交換器、AP", "match": ["ubiquiti", "unifi", "ubnt"],
     "snmp": ["UniFi Network：Settings ▸ System（或 Settings ▸ Network 依版本）找到 SNMP，開啟 SNMPv1/v2c 並設定 community「{COMM}」。",
              "UniFi 交換器與 AP 也會套用同一組設定。"],
     "flow": "IPFIX（UniFi Network 9.1 以後的閘道器）",
     "flow_steps": ["Settings ▸ CyberSecure ▸ Traffic Logging：開啟 NetFlow（IPFIX）。", "收集器填 {IP}，埠 {NF}。"],
     "doc": "https://help.ui.com/hc/en-us/articles/32201256219799"},

    {"id": "edgerouter", "name": "Ubiquiti EdgeRouter", "kind": "路由器（EdgeOS）", "match": ["edgerouter", "edgeos"],
     "snmp": ["System ▸ SNMP 開啟並設定 community，或用 CLI。"],
     "snmp_cli": "configure\nset service snmp community {COMM} authorization ro\nset service snmp community {COMM} client {IP}\ncommit ; save",
     "flow": "NetFlow v9",
     "flow_cli": "configure\nset system flow-accounting interface eth1\nset system flow-accounting netflow version 9\nset system flow-accounting netflow server {IP} port {NF}\ncommit ; save",
     "flow_steps": ["把 eth1 換成連接內網的介面。"]},

    {"id": "pfsense", "name": "pfSense", "kind": "防火牆", "match": ["pfsense", "netgate"],
     "snmp": ["Services ▸ SNMP：Enable，Read Community String 填「{COMM}」，Bind Interfaces 選 LAN。"],
     "flow": "NetFlow v9／IPFIX（softflowd 套件）",
     "flow_steps": ["System ▸ Package Manager 安裝 softflowd。", "Services ▸ softflowd：Interface 選 LAN，Destination Host 填 {IP}，Port {NF}，NetFlow version 選 9 或 IPFIX，儲存。"]},

    {"id": "opnsense", "name": "OPNsense", "kind": "防火牆", "match": ["opnsense", "deciso"],
     "snmp": ["System ▸ Firmware ▸ Plugins 安裝 os-net-snmp。", "Services ▸ Net-SNMP：Enable，community 填「{COMM}」。"],
     "flow": "NetFlow v5／v9（內建）",
     "flow_steps": ["Reporting ▸ NetFlow：Interfaces 選 LAN（可多選）。", "WAN 介面若也選了，放進 Egress only 避免重複計算。",
                    "Version 選 v9，Destinations 輸入 {IP}:{NF} 後按 Enter，套用。"],
     "doc": "https://docs.opnsense.org/manual/how-tos/netflow_exporter.html"},

    {"id": "sophos", "name": "Sophos Firewall", "kind": "防火牆（SFOS／XGS）", "match": ["sophos"],
     "snmp": ["System services ▸ SNMP（或 Administration ▸ SNMP）：開啟 Agent，新增 community「{COMM}」，Manager IP 填 {IP}，只給查詢權限。",
              "Administration ▸ Device access：LAN zone 勾選 SNMP。"],
     "flow": "NetFlow v5",
     "flow_steps": ["System ▸ Administration ▸ Netflow：Add，Netflow server IP 填 {IP}，port {NF}，儲存。",
                    "只會匯出有開記錄的規則：Rules and policies ▸ Firewall rules，要統計的規則開啟 Log firewall traffic。",
                    "NetFlow v5 沒有 IPv6。"],
     "doc": "https://www.avanet.com/en/kb/sophos-firewall-netflow-monitoring/"},

    {"id": "paloalto", "name": "Palo Alto Networks", "kind": "防火牆（PAN-OS）", "match": ["palo alto", "paloalto"],
     "snmp": ["Device ▸ Setup ▸ Operations ▸ SNMP Setup：選 V2c 填 community「{COMM}」（或 V3）。",
              "Network ▸ Network Profiles ▸ Interface Mgmt：建立允許 SNMP 的設定檔並套到 LAN 介面，Permitted IP 加 {IP}。"],
     "flow": "NetFlow v9",
     "flow_steps": ["Device ▸ Server Profiles ▸ NetFlow：新增，Server 填 {IP}、Port {NF}。",
                    "Network ▸ Interfaces：編輯 LAN 介面 ▸ Advanced ▸ NetFlow Profile 選剛才的設定，Commit。"]},

    {"id": "checkpoint", "name": "Check Point", "kind": "防火牆（Gaia）", "match": ["check point", "checkpoint"],
     "snmp": ["Gaia Portal ▸ System Management ▸ SNMP：開啟 SNMP Agent，Version 選 v2/v3，Read Only Community 填「{COMM}」。"],
     "flow": "NetFlow v9／IPFIX",
     "flow_steps": ["Gaia Portal ▸ Network Management ▸ NetFlow Export：新增收集器 {IP}、Port {NF}，格式選 NetFlow V9 或 IPFIX。"]},

    {"id": "juniper", "name": "Juniper", "kind": "交換器（EX）、防火牆（SRX）", "match": ["juniper", "junos"],
     "snmp": ["只允許 {IP} 查詢。"],
     "snmp_cli": "set snmp community {COMM} authorization read-only\nset snmp community {COMM} clients {IP}/32\nset protocols lldp interface all\ncommit",
     "flow": "sFlow（EX 交換器）；SRX 用 J-Flow v9／IPFIX",
     "flow_steps": ["EX 交換器：在上行與要觀察的介面開 sFlow。"],
     "flow_cli": "set protocols sflow collector {IP} udp-port {SF}\nset protocols sflow sample-rate ingress 1024\nset protocols sflow interfaces ge-0/0/0\ncommit"},

    {"id": "aruba", "name": "HPE Aruba", "kind": "交換器（AOS-S／AOS-CX）", "match": ["aruba", "hpe", "procurve"],
     "snmp": ["AOS-S（2530／2930 等）："],
     "snmp_cli": "snmp-server community \"{COMM}\" operator restricted\nsnmp-server host {IP} community \"{COMM}\"\nlldp run",
     "flow": "sFlow",
     "flow_steps": ["AOS-S：設定 sFlow 收集器並在各埠開啟取樣。AOS-CX：sflow collector {IP} 後 sflow enable。"],
     "flow_cli": "sflow 1 destination {IP} {SF}\ninterface 1-24 sflow 1 sampling 1024\ninterface 1-24 sflow 1 polling 30"},

    {"id": "h3c", "name": "H3C／HPE Comware", "kind": "交換器、路由器", "match": ["h3c", "comware"],
     "snmp": ["只允許唯讀查詢。"],
     "snmp_cli": "snmp-agent\nsnmp-agent sys-info version v2c\nsnmp-agent community read {COMM}\nlldp global enable",
     "flow": "sFlow（交換器）／NetStream（路由器，相當於 NetFlow）",
     "flow_cli": "sflow agent ip <交換器管理IP>\nsflow collector 1 ip {IP} port {SF}\ninterface GigabitEthernet1/0/1\n sflow sampling-rate 4096\n sflow flow collector 1",
     "flow_steps": ["在要觀察的埠（例如上行埠）開啟 sFlow 取樣。"]},

    {"id": "huawei", "name": "華為 Huawei", "kind": "交換器、路由器、防火牆", "match": ["huawei"],
     "snmp": ["只允許唯讀查詢。"],
     "snmp_cli": "snmp-agent\nsnmp-agent sys-info version v2c\nsnmp-agent community read cipher {COMM}\nlldp enable",
     "flow": "sFlow（交換器）／NetStream（路由器、防火牆）",
     "flow_cli": "sflow agent ip <交換器管理IP>\nsflow collector 1 ip {IP} udp-port {SF}\ninterface GigabitEthernet0/0/1\n sflow sampling collector 1\n sflow sampling rate 4096",
     "flow_steps": ["在要觀察的埠開啟 sFlow 取樣。"]},

    {"id": "ruckus", "name": "Ruckus ICX", "kind": "交換器", "match": ["ruckus", "brocade"],
     "snmp": ["只允許唯讀查詢。"],
     "snmp_cli": "snmp-server community {COMM} ro\nlldp run",
     "flow": "sFlow",
     "flow_cli": "sflow destination {IP} {SF}\nsflow enable\ninterface ethernet 1/1/1\n sflow forwarding",
     "flow_steps": ["在要觀察的埠開啟 sflow forwarding。"]},

    {"id": "tplink", "name": "TP-Link Omada／JetStream", "kind": "交換器、閘道器", "match": ["tp-link", "tplink", "omada"],
     "snmp": ["單機管理：Maintenance ▸ SNMP ▸ Global Config 開啟，Community 新增「{COMM}」唯讀。",
              "Omada 控制器：Settings ▸ Services ▸ SNMP 開啟並設定 community，會套用到所有設備。"],
     "flow": "部分 JetStream L2+／L3 交換器支援 sFlow；Omada 閘道器目前沒有 NetFlow",
     "flow_steps": ["支援 sFlow 的機型：Maintenance ▸ sFlow，Collector 填 {IP}、Port {SF}，再到 Sampler 在上行埠開啟取樣。"]},

    {"id": "zyxel", "name": "Zyxel", "kind": "防火牆（USG FLEX／ATP）、交換器", "match": ["zyxel"],
     "snmp": ["防火牆：System ▸ SNMP 開啟，設定 Get Community「{COMM}」，Service Control 只允許 LAN。",
              "交換器：Management ▸ SNMP（或 Advanced Application ▸ SNMP）設定唯讀 community。"],
     "flow": "多數機型沒有 NetFlow／sFlow；可以看埠流量（SNMP）",
     "flow_steps": ["沒有流量匯出的話，「誰在用」可以改看上游防火牆或支援 sFlow 的交換器。"]},

    {"id": "draytek", "name": "DrayTek Vigor", "kind": "路由器", "match": ["draytek", "vigor"],
     "snmp": ["System Maintenance ▸ SNMP：Enable SNMP Agent，Get Community 填「{COMM}」，Manager Host IP 填 {IP}。"],
     "flow": "沒有 NetFlow／sFlow",
     "flow_steps": ["可以看 WAN／LAN 埠流量（SNMP）；要知道誰在用，請改用支援流量匯出的設備。"]},

    {"id": "netgear", "name": "NETGEAR", "kind": "網管交換器", "match": ["netgear"],
     "snmp": ["System ▸ SNMP ▸ SNMP V1/V2 ▸ Community Configuration：新增唯讀 community「{COMM}」，IP 填 {IP}。"],
     "flow": "部分 M4300／M4350 等支援 sFlow",
     "flow_steps": ["Monitoring ▸ sFlow：Receiver 填 {IP}、Port {SF}，在上行埠設定 Sampler。"]},

    {"id": "dlink", "name": "D-Link", "kind": "網管交換器", "match": ["d-link", "dlink"],
     "snmp": ["Management ▸ SNMP Settings：SNMP Global State 開啟，Community 新增「{COMM}」read only。"],
     "flow": "DGS-3000 以上等系列支援 sFlow",
     "flow_steps": ["支援的機型：sFlow ▸ Collector 填 {IP}、Port {SF}，並在埠上開啟 Flow Sampler。"]},

    {"id": "synology", "name": "Synology NAS", "kind": "NAS", "match": ["synology"],
     "snmp": ["控制台 ▸ 終端機 & SNMP ▸ SNMP：啟動 SNMP 服務，勾選 SNMPv1/v2c，community 填「{COMM}」。",
              "也可以改用「加入 SSH 設備…」讀流量（控制台 ▸ 終端機 開啟 SSH）。"],
     "flow": "沒有流量匯出", "flow_steps": []},

    {"id": "asus", "name": "ASUS 家用路由器", "kind": "家用路由器", "match": ["asus"],
     "snmp": ["多數機型沒有 SNMP，請改用 netmap.exe「監控服務 ▸ 加入 SSH 設備…」。",
              "開 SSH：系統管理 ▸ 系統設定 ▸ 啟用 SSH 選「只限 LAN」。測完不用時記得關閉。"],
     "flow": "沒有流量匯出", "flow_steps": []},

    {"id": "windows", "name": "Windows 電腦／伺服器", "kind": "電腦", "match": ["microsoft", "windows"],
     "snmp": ["設定 ▸ 系統 ▸ 選用功能 ▸ 新增「簡易網路管理通訊協定（SNMP）」。",
              "服務（services.msc）▸ SNMP Service ▸ 安全性：新增唯讀 community「{COMM}」，「接受來自這些主機」加入 {IP}。"],
     "flow": "沒有流量匯出", "flow_steps": []},

    {"id": "linux", "name": "Linux 主機", "kind": "伺服器", "match": ["linux", "ubuntu", "debian", "red hat", "centos"],
     "snmp": ["最簡單：用 netmap.exe「加入 SSH 設備…」讀流量，不用裝東西。",
              "或安裝 snmpd，在 /etc/snmp/snmpd.conf 加入 rocommunity {COMM} {IP}，重新啟動 snmpd。"],
     "flow": "可安裝 softflowd 匯出 NetFlow",
     "flow_cli": "sudo apt install softflowd\nsudo softflowd -i eth0 -n {IP}:{NF} -v 9"},
]

COMMON = {
    "snmp_tip": "建議所有設備用同一組唯讀 community（例如「{COMM}」）或同一組 SNMPv3 帳密，並只允許 netmap.exe 那台電腦（{IP}）查詢。不要用 public，也不要開寫入權限。",
    "flow_tip": "流量匯出只要開在一台設備上就夠了（通常是防火牆，在 LAN 介面開）。同一台設備的同一份流量若在多個介面都匯出，可能會重複計算。",
}


def as_json():
    import json
    return json.dumps({"vendors": VENDORS, "common": COMMON}, ensure_ascii=False, separators=(",", ":"))


def fill(text, ip="（netmap.exe 那台電腦的 IP）", nf=2055, sf=6343, comm="netmap-ro"):
    return text.replace("{IP}", ip).replace("{NF}", str(nf)).replace("{SF}", str(sf)).replace("{COMM}", comm)


def render_text(v, **kw):
    """給 netmap.exe 視窗顯示的純文字。"""
    out = [f"{v['name']}（{v['kind']}）", ""]
    out.append("■ 開啟 SNMP（自動畫圖、埠流量）")
    out += [f"  {i}. {fill(t, **kw)}" for i, t in enumerate(v.get("snmp", []), 1)]
    if v.get("snmp_cli"): out += ["", "  CLI："] + ["    " + l for l in fill(v["snmp_cli"], **kw).splitlines()]
    out += ["", f"■ 流量匯出（誰在用）：{v.get('flow', '')}"]
    out += [f"  {i}. {fill(t, **kw)}" for i, t in enumerate(v.get("flow_steps", []), 1)]
    if v.get("flow_cli"): out += ["", "  CLI："] + ["    " + l for l in fill(v["flow_cli"], **kw).splitlines()]
    if v.get("doc"): out += ["", f"原廠說明：{v['doc']}"]
    out += ["", "※ " + fill(COMMON["snmp_tip"], **kw), "※ " + fill(COMMON["flow_tip"], **kw), "※ 選單位置依韌體版本可能略有不同。"]
    return "\n".join(out)
