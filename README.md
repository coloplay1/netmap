# 機房線路對應圖

IT 用的網路線路對應工具：建立防火牆、路由器、Switch、Hub、AP、配線架、座位資訊座與終端設備，埠對埠拖曳接線，點任一網路埠即可追蹤「Switch 埠 ➔ 配線架 ➔ 座位 ➔ 電腦」整條路徑。

🌐 **線上使用：<https://coloplay1.github.io/netmap/>**（免安裝，直接用瀏覽器開啟）

📖 **[使用手冊（圖文教學）](https://coloplay1.github.io/netmap/manual.html)** · [版本紀錄](https://coloplay1.github.io/netmap/manual.html#changelog) · [下載 netmap.exe](https://github.com/coloplay1/netmap/releases/latest/download/netmap.exe)

## 功能

- **開始頁**：先選用法——「網頁版」手動畫圖，或「本地端 netmap.exe」自動掃描與監控（介紹、下載、偵測這台電腦的 netmap.exe；從監控服務打開時顯示監控狀態）。網頁版分成「新增」（空白畫面、基本骨架）、「匯入」（專案檔、LLDP/CDP、JSON 文字）、「範例」（辦公室、餐飲門市、診所、工廠 IT＋OT、學校電腦教室）三區；第一次開啟時畫布是空白的
- **介面**：深色浮動面板（右上角可切淺色），畫布佔滿整個畫面；設備以擬真圖示呈現，雙擊可切換成網路埠模式，「顯示圖層」可一鍵全部收成圖示或全部展開網路埠，資訊圖層可全部顯示／全部取消
- **加設備**：從左側設備列拖到畫布指定位置，或點一下自動放在畫面空白處；也可在畫布按右鍵或 A 鍵叫出設備選單
- **接線**：從埠拖曳到埠接線，拖到收成圖示的設備會自動接到空埠；拖曳已接線的埠可改插；SFP 對 SFP 自動判斷為光纖
- **情境設定列**：點埠、多選埠或點線時，直接在旁邊彈出小工具列設定 VLAN、PoE、LACP、線材與方向
- **畫布工具**：右下角浮動工具列集中復原、縮放、全覽、走線方式、圖層與自動排列；拖曳空白處平移畫布，「?」查看所有操作
- **線條樣式**：依自訂顏色、線材（Cat5e/6/6A、單模/多模光纖、DAC、Console）或 VLAN 自動上色；方向箭頭與速率標示
- **走線**：曲線或直角（自動分道、避開設備）；線上雙擊新增錨點手動拉走線槽
- **機櫃視圖**：42U 等機櫃，設備依 U 位疊放，拖曳上下架
- **埠位屬性**：PoE、LACP 群組、Access／Trunk、Tagged VLAN；Shift 多選或框選批次設定
- **型號範本**：常見型號自動帶入埠位與 PoE 配置，另有快速埠位預設
- **資訊圖層**：一鍵切換 IP、MAC、Gateway、位置、VLAN、線號、速率、PoE／LACP 圖示
- **搜尋對焦**：輸入線號、IP、設備或廠牌，自動縮放對焦並淡出無關設備
- **唯讀模式與 QR Code**：現場查線不誤觸；整份配置或單一設備可產生網址與 QR Code
- **匯出**：配線表 CSV、完整路徑 CSV、設備清單 CSV、拓樸圖 SVG／PNG、JSON 專案檔
- **多張圖（頁面）**：樓層、機房、分公司分開畫，跨頁面的線顯示「→ 對面頁面」連接標籤，點一下跳過去；查線跨頁面走完整條
- **光纖收容箱與光纖束**：一條 12／24／48 芯光纜一次建立，每一芯標 TIA-598 色碼，畫成一條粗線，點開看每一芯接到哪
- **平行線收成一條**：同一對設備之間的多條線（LACP、備援）收成一條粗線；48 埠設備在縮小畫面或平板上點埠時放大選埠
- **歷史版本**：預覽舊版本再一鍵還原；線上版也會在瀏覽器自動留版本
- **資料檢查與變更紀錄**：重複 IP／MAC／線號、VLAN 不一致等一次列出；每台設備、每條線都能看自己的修改紀錄
- **線標列印**：A4 標籤紙（含 QR Code）或 Brother P-touch Editor CSV
- **LLDP／CDP 匯入**：貼上 `show lldp neighbors`／`show cdp neighbors` 或 CSV 自動產生設備與連線

資料存在瀏覽器（localStorage），可用「檔案」選單下載／開啟 JSON 專案檔備份。型號埠位依常見規格整理，實際請以原廠規格為準。

單一 `index.html`，不需建置，開啟 GitHub Pages 即可使用。

## 故障查線

右下角「查線」→ 點回報有問題的設備，會列出它到網路入口的每一段（網卡、跳線、資訊座、牆內線、配線架、Switch 埠、上行線、防火牆、ISP）：

- 每段可標「正常／可疑／故障」並寫備註，畫布同步上色
- 自動健檢：VLAN 不一致、Trunk 沒帶 VLAN、PoE 設備接到沒開 PoE 的埠、LACP 接錯、銅線超過 100 m、光纖接 RJ45、IP 重複、Gateway 不在圖上
- 建議下一步：先查健檢發現的疑點，再用二分法挑中間段
- 影響範圍：標成故障後，列出從網路入口到不了的設備；設備面板的「如果這台壞了」可模擬單點故障
- 結案後紀錄保留在「線路表 ▸ 故障紀錄」，可匯出 CSV；紀錄會跟著專案 JSON 與分享連結

## SNMP 自動掃描

`tools/netmap-snmp/` 是在內網電腦執行的掃描程式（SNMP v1／v2c 只用 Python 標準函式庫，v3 需 `pip install pysnmp`），
讀取 LLDP／CDP、IF-MIB、ENTITY-MIB、Q-BRIDGE、PoE、LAG、MAC 表與 ARP，輸出可直接匯入的 JSON。

- Python 版：[tools/netmap-snmp.zip](https://coloplay1.github.io/netmap/tools/netmap-snmp.zip)
- Windows 執行檔：[Releases](https://github.com/coloplay1/netmap/releases/latest)（由 GitHub Actions 自動建置）

```
python netmap_snmp.py 192.168.1.1 -c public          # 從核心 Switch 開始，沿 LLDP 自動擴展
python netmap_snmp.py 192.168.1.0/24 -c public       # 掃整個網段
python netmap_snmp.py 10.0.0.1 -v 3 -u netmon -a SHA -A 認證密碼 -x AES -X 加密密碼
```

## Windows 程式：netmap.exe（SNMP 掃描＋監控服務）

[下載 netmap.exe](https://github.com/coloplay1/netmap/releases/latest/download/netmap.exe)

- **SNMP 掃描**（視窗介面）：輸入核心 Switch IP 與 community／SNMPv3 帳密，自動找出設備與連線
- **監控服務**：常駐在內網一台 Windows 電腦，提供 `http://<IP>:8080/` 網頁版（多人共用同一張圖），
  每 30～300 秒讀取每個埠的流量（IF-MIB HC 計數器）、上下線、錯誤封包，保留歷史（SQLite，預設 7 天）
  - 線路依使用率變色（綠 < 30%、黃 30–70%、紅 > 70%），離線埠紅燈、沒回應的設備標「離線」
  - 點埠可看即時流量與 24 小時曲線；離線埠、錯誤封包、壅塞會進入故障查線的自動健檢
  - 跑 netmap.exe 的電腦自動監控自己的網卡流量；即時狀態卡片顯示今日流量縮圖
  - MRTG 流量圖：每個埠的日（5 分鐘）／週（30 分鐘）／月（2 小時）／年（1 天）圖，最大／平均／目前值與使用率，保存約 2 年；網址加 `#mrtg=all` 直接打開總覽
  - 右側分成「設備資訊」與「網路流量」分頁；無線連線（Wi-Fi 2.4G／5G／6G）畫成虛線並納入查線；SSH 監控的路由器可列出有線／無線用戶端並一鍵套用到圖上
  - SSH 流量監控：沒有 SNMP 的家用路由器（ASUS 自動辨識 WAN／LAN／Wi-Fi）、Linux、NAS、OpenWrt 用 SSH 讀 `/proc/net/dev`，一樣有即時流量與流量圖；帳密以 DPAPI 加密、記住主機金鑰
  - 誰在用流量：接收 NetFlow v5／v9、IPFIX、sFlow（UDP 2055／6343），每台電腦的下載／上傳排行、連去哪裡、用什麼服務，以及在路徑每一段佔多少；接在傻瓜 Switch 後的電腦也看得到
  - 各廠牌設定教學：SonicWall、FortiGate、Cisco、Meraki、MikroTik、UniFi、pfSense、OPNsense、Sophos、Palo Alto、Check Point、Juniper、Aruba、H3C、Huawei、Ruckus、TP-Link 等 26 種，怎麼開 SNMP 與流量匯出
  - Ping 心跳：所有有 IP 的設備都有綠／黃／紅燈號與延遲曲線，不需要 SNMP
  - 告警通知：設備斷線、主幹埠離線、新設備加入時送到 Telegram、Discord、Slack、Teams、LINE（Messaging API）、Email 或自訂 Webhook；事件紀錄保留 180 天
  - 歷史版本：每次修改記下是誰、改了什麼，可預覽再還原
  - 圖面比對：定期讀 LLDP／CDP 與 MAC 表和圖上的線對帳，找出接錯、改線沒更新、圖上沒畫的線，每條線標出是否實際確認過；IP 衝突偵測
  - 網路上的設備：從 ARP 表與路由器用戶端清單找出新加入、很久沒出現、不在圖上的設備
  - 權限：管理密碼（其他電腦登入後才能編輯）、只能看的檢視連結與 QR Code；預設只有服務主機能編輯
  - 帳密以 Windows DPAPI 加密保存；資料在 `%APPDATA%\netmap`
