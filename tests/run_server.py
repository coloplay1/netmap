# CI 用：啟動一個帶範例圖的監控服務（埠 18799），並測試「搬到背景服務」與「掃描結果送到背景服務」。
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "netmap-snmp"))
import netmap_server as S
st = S.Store(tempfile.mkdtemp()); st.settings.update(port=18799, interval=30, lan_edit=True)
st.set_project({"devices": [{"id": "d1", "type": "sw", "name": "SW-01", "ip": "192.0.2.2", "x": 0, "y": 0, "ports": [{"id": "p1", "label": "1"}, {"id": "p2", "label": "2"}]},
                            {"id": "d2", "type": "end", "name": "PC-01", "ip": "192.0.2.10", "x": 0, "y": 200, "ports": [{"id": "p3", "label": "LAN"}]}],
                "cables": [{"id": "c1", "a": "p1", "b": "p3", "label": "C1"}]})
sv = S.Service(st, log=lambda m: None); sv.start(); time.sleep(1)
url = "http://127.0.0.1:18799/"
w = S.Store(tempfile.mkdtemp()); w.set_project({"devices": [{"id": "x", "type": "fw", "name": "WIN-FW", "ports": []}], "cables": []})
res = S.push_projects_to(w, url); print("push", res); assert any("視窗版" in r for _, r in res)
c, pl = S._svc_call(url, "/api/projects"); assert len(pl["list"]) == 2 and pl["current"] == st.pid
msg = S.svc_apply_scan(url, {"source": "netmap-discover", "devices": [{"id": "n", "type": "end", "name": "NEW", "ip": "192.0.2.99", "mac": "02:00:00:00:00:99", "ports": []}], "cables": []}, "merge"); print(msg)
assert any(d["name"] == "NEW" for d in st.project["devices"])
print("server ready", flush=True)
if "--serve" in sys.argv:
    while True: time.sleep(60)
sv.stop()
