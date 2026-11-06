# -*- coding: utf-8 -*-
"""建置時執行：下載 IEEE OUI（MAC 前 3 碼 → 廠商）資料表，輸出 oui.json.gz 打包進 netmap.exe。下載失敗時輸出空表，不影響建置。"""
import gzip, json, re, sys, urllib.request
SOURCES = ["https://standards-oui.ieee.org/oui/oui.txt", "https://www.wireshark.org/download/automated/data/manuf"]
def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (netmap build)"})
    return urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
table = {}
for url in SOURCES:
    try:
        txt = fetch(url)
    except Exception as e:
        print("skip", url, e); continue
    for line in txt.splitlines():
        m = re.match(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$", line.strip())
        if m: table[(m.group(1) + m.group(2) + m.group(3))] = m.group(4).strip(); continue
        m = re.match(r"^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\t([^\t]+)(?:\t(.+))?$", line)
        if m:
            k = (m.group(1) + m.group(2) + m.group(3)).upper()
            table.setdefault(k, (m.group(5) or m.group(4)).strip())
    if len(table) > 10000: break
out = sys.argv[1] if len(sys.argv) > 1 else "oui.json.gz"
with gzip.open(out, "wt", encoding="utf-8") as f: json.dump(table, f, ensure_ascii=False, separators=(",", ":"))
print("OUI entries:", len(table))
