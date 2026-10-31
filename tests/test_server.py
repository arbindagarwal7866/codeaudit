import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import codeaudit.server as server


def test_web_ui_flow(shopkart, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "OUT_ROOT", tmp_path / "web")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def post(path, body):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
        return json.loads(urllib.request.urlopen(req).read())

    def get(path):
        return json.loads(urllib.request.urlopen(base + path).read())

    try:
        assert b"Run audit" in urllib.request.urlopen(base + "/").read()
        assert any(p["name"] == "offline" for p in get("/api/providers")["providers"])
        jid = post("/api/audit", {"repo": str(shopkart), "provider": "offline", "refactor_k": 4})["job"]
        for _ in range(100):
            job = get(f"/api/jobs/{jid}")
            if job["status"] != "running":
                break
            time.sleep(0.2)
        assert job["status"] == "done", job.get("error")
        assert len(job["patches"]) == 4
        fid = job["patches"][0]["id"]
        assert post(f"/api/jobs/{jid}/pr", {"finding": fid})["ok"]                   # sandbox branch
        r = post(f"/api/jobs/{jid}/apply", {"finding": fid})
        assert r["ok"], r
        assert "?" in (shopkart / "shopkart" / "db.py").read_text()                  # fix landed in the files
        assert urllib.request.urlopen(base + f"/jobs/{jid}/report").status == 200
    finally:
        srv.shutdown()
