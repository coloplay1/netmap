# -*- coding: utf-8 -*-
"""CI 自我測試：Ping、告警訊息格式、歷史版本、權限（管理密碼、檢視連結）、網路上的設備。"""
import json, tempfile, time, urllib.request, urllib.error
import netmap_alert as na, netmap_server as S

rtt = na.ping("127.0.0.1", 1.0)
print("ping 127.0.0.1", rtt, na.ping_method()); assert rtt is not None
for t in ("telegram", "discord", "slack", "teams", "line", "webhook"):
    u, h, b = na.build_request({"type": t, "token": "T", "url": "https://example.invalid/x", "chat": "1", "to": "U"}, "標題", "內文", [{"kind": "test", "name": "n"}])
    json.loads(b)
print(na.compose([{"kind": "down", "name": "SW", "ip": "10.0.0.2", "ts": 0}, {"kind": "port_down", "name": "FW", "port_name": "埠 1", "ts": 0}]))

st = S.Store(tempfile.mkdtemp()); st.settings["port"] = 18766
proj = {"devices": [{"id": "d1", "type": "sw", "name": "SW", "ip": "127.0.0.1", "ports": [{"id": "p1", "label": "1"}]}], "cables": []}
st.set_project(proj, None, "ci"); st.REV_MERGE_SECS = 0
st.set_project({**proj, "devices": proj["devices"] + [{"id": "d2", "type": "ap", "name": "AP", "ports": []}]}, None, "ci2")
sv = S.Service(st, log=print); sv.start(); time.sleep(1)
B = "http://127.0.0.1:18766"
def call(path, body=None, method=None):
    r = urllib.request.Request(B + path, data=json.dumps(body).encode() if body is not None else None, method=method or ("POST" if body is not None else "GET"),
                               headers={"Content-Type": "application/json", "X-Netmap": "1"})
    return json.load(urllib.request.urlopen(r))
revs = call("/api/revs")["revs"]; print([(r["rev"], r["summary"]) for r in revs]); assert len(revs) == 2 and "AP" in revs[0]["summary"]
assert call("/api/revs/restore", {"rev": 1})["rev"] == 3
sv.pinger.cycle(); time.sleep(0.2)
s = call("/api/status"); print("ping", s["ping"]); assert s["ping"]["d1"]["rtt"] is not None
r = call("/api/settings", {"password": {"new": "abcdef12"}, "view_required": True}, "PUT"); assert r["auth"]["has_password"] and r["auth"]["view_links"]
try:
    urllib.request.urlopen(urllib.request.Request(B + "/api/project", data=b"{}", method="PUT")); raise SystemExit("CSRF header not enforced")
except urllib.error.HTTPError as e: assert e.code == 403
print(st.seen_update([{"mac": "00:11:22:33:44:55", "ip": "10.0.0.9"}], "ci"))
sv.stop(); print("ops self-test OK")
c = S.probe_candidates({"devices": [{"id": "a", "type": "sw", "ip": "10.0.0.2", "monitor": False}, {"id": "b", "type": "sw", "ip": "10.0.0.3"},
                                    {"id": "c", "type": "end", "kind": "NAS", "ip": "10.0.0.4"}, {"id": "d", "type": "end", "kind": "PC 桌機", "ip": "10.0.0.5"}]}, set())
assert [d["id"] for d in c] == ["a", "c"], c; print("probe candidates OK")
