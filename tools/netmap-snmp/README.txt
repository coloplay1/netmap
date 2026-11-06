netmap：機房線路對應圖 SNMP 掃描與監控程式
https://coloplay1.github.io/netmap/

這支程式在你們內網的電腦上執行，用 SNMP 讀取防火牆、Switch、AP 的資料，
產生一個 .json 檔，再到網頁「匯入 ▸ 開啟專案檔」就會自動畫出整張網路圖。
只讀取，不會修改任何設備設定。

【需要】
- Python 3.8 以上（Windows 到 https://www.python.org/downloads/ 安裝，安裝時勾選「Add python.exe to PATH」）
- 設備開啟 SNMP（v2c community 或 v3 帳密，唯讀即可），並建議開啟 LLDP（Cisco 可用 CDP）
- 執行的電腦可以連到設備的 UDP 161 埠
- SNMPv1 / v2c 不需要安裝其他套件；SNMPv3 需要先執行：pip install pysnmp

【視窗版（建議）】
Windows：雙擊 netmap.exe（或 Python 版的 run-app-windows.bat）開啟視窗：
  「SNMP 掃描」分頁：輸入核心 Switch 的 IP 與 community，按「開始掃描」，完成後按「設為監控的圖」。
  「監控服務」分頁：按「啟動服務」，同一個內網的電腦用瀏覽器打開顯示的網址（例如 http://192.168.1.20:8080/），
                     就能看到同一張圖，以及每個埠的流量、使用率、上下線狀態與 24 小時曲線。
  可勾選「Windows 開機時自動執行」。第一次啟動服務時 Windows 防火牆會詢問，請按「允許存取」。
  預設只有這台電腦可以編輯圖，其他電腦只能看；要讓大家都能改，勾選「允許內網其他電腦編輯圖」。
  資料（圖、流量紀錄、加密後的帳密）存在 %APPDATA%\netmap。

【沒有 SNMP 的網路（家用、小型辦公室）】
家用路由器、電腦、手機通常不支援 SNMP，SNMP 掃描會找不到東西。這時改用「網段探索」：
  視窗版：在「掃描」分頁選「網段探索」，不填目標就會掃這台電腦所在的網段。
  命令列：python netmap_snmp.py --discover          （或 --discover 192.168.1.0/24）
會用 ping、常見連接埠與 ARP 表列出在線的設備（IP、MAC、廠牌、名稱），並依開放的服務推測種類。
看不出誰接在哪個埠，預設先把設備都接到路由器，之後請在網頁上調整。
SNMP 掃描沒有回應時，程式也會自動檢查設備是否在線，告訴你是「沒開 SNMP」還是「連不到」。

【收集樣本（給 log 分析與設定檔備份開發用）】
netmap.exe 的「收集樣本」分頁：
  ① 收集 log：這台電腦暫時當 Syslog（UDP 514）／SNMP Trap（UDP 162）接收器，把設備的 log 目的地設成這台電腦，
     收到的內容會即時顯示並存成 %APPDATA%\netmap\samples\syslog-日期.log、trap-日期.log。
  ② 登入紀錄：輸入設備 IP 與帳密，自動用 SSH 登入並執行 show running-config 等指令（自動處理 --More-- 與 enable），
     整段畫面存成 login-IP-日期.txt；密碼、community、金鑰會自動換成 ***（傳出前仍請自己看過）。密碼不會存檔。
  Python 版需要另外安裝：pip install paramiko

【命令列版的用法】
Windows：雙擊 run-windows.bat，依提示輸入要掃描的 IP 或網段、community。
macOS / Linux：在終端機執行 ./run-mac-linux.sh
完成後會在同一個資料夾產生 netmap-scan-日期時間.json。

【命令列用法】
  python netmap_snmp.py 192.168.1.1                     從一台核心 Switch 開始，自動沿著 LLDP 找到其他設備
  python netmap_snmp.py 192.168.1.0/24 -c mycommunity   掃描整個網段
  python netmap_snmp.py 10.0.0.1-30 10.0.1.1            範圍與多個目標
  python netmap_snmp.py 10.0.0.1 -v 3 -u netmon -a SHA -A 認證密碼 -x AES -X 加密密碼
  python netmap_snmp.py 10.0.0.1 -o 機房.json --no-fdb  不推斷終端設備（只畫網路設備之間的線）

  其他選項：-t 逾時秒數（預設 2）、--no-follow 不自動追 LLDP 鄰居、--max-devices 上限、--raw 另存原始資料。
  輸入 python netmap_snmp.py -h 看全部選項。

【會讀到哪些資料】
- 系統名稱、描述、位置、型號、序號 → 設備名稱、廠牌型號
- 介面名稱、速率、狀態、描述 → 網路埠
- LLDP / CDP 鄰居 → 設備之間的連線（沒有掃到的鄰居，例如 AP、IP 電話，也會依鄰居資訊建立）
- VLAN（PVID、Trunk 帶的 VLAN）、PoE、LACP
- MAC 表 + ARP 表 → 電腦、印表機等終端設備接在哪個埠、IP 是多少
  一個埠學到多個 MAC 時，會畫成「未管理交換器」再接出各台設備

【限制】
- 配線架、資訊座這類被動元件不會回應 SNMP，匯入後請手動補上（可以把線拖到配線架的埠上）。
- 沒開 LLDP / CDP 的設備之間，只能從 MAC 表推斷，可能不完整。
- 終端設備只會有 MAC 與 IP，名稱、種類請匯入後再補。
