"""Shared fixtures: a disposable copy of the demo repo and fake LLM servers that speak the real
Anthropic Messages / OpenAI Chat Completions wire formats (so the HTTP client is really exercised)."""
import json
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SHOPKART = ROOT / "examples" / "shopkart"
LABELS = ROOT / "examples" / "shopkart_labels.csv"
FIXTURE = Path(__file__).parent / "fixture_repo"


@pytest.fixture
def shopkart(tmp_path):
    dst = tmp_path / "shopkart"
    shutil.copytree(SHOPKART, dst, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return dst


# ---------------------------------------------------------------- a scripted "LLM"
GOOD_GET_USER = '''```python
def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    return cur.fetchone()
```'''
BAD_GET_USER = '''```python
def get_user(conn, name):
    return None
```'''


def brain(system: str, messages: list) -> str:
    first = messages[0]["content"] if isinstance(messages[0]["content"], str) else str(messages[0]["content"])
    last = messages[-1]["content"] if isinstance(messages[-1]["content"], str) else str(messages[-1]["content"])
    if "triaging static-analysis findings" in system:
        fp_signals = ["constant argument", "pass constants", "looks like a URL", "Possibly used dynamically"]
        fp = any(s in first for s in fp_signals) or (
            first.startswith("## Finding\nWEAK_HASH") and "only used as a fast cache key" in first)
        verdict = "FALSE_POSITIVE" if fp else "TRUE_POSITIVE"
        return f'Here is my assessment:\n```json\n{{"verdict": "{verdict}", "confidence": 0.9, "reason": "scripted"}}\n```'
    if "software architect" in system:
        return json.dumps({"summary": "s", "root_cause": "r", "impact": "i", "cwe": None,
                           "fix_plan": ["do the fix"], "effort": "small", "refactorable": True})
    if "autonomous refactoring agent" in system:
        target = re.search(r"Target symbol id: (\S+)", first).group(1)
        n_assistant = sum(1 for m in messages if m["role"] == "assistant")
        if n_assistant == 0:
            return json.dumps({"tool": "get_callers", "symbol": target})
        if target.endswith(":get_user"):
            return BAD_GET_USER if "rejected" not in last else GOOD_GET_USER
        if target.endswith(":find_orders"):
            return "```python\ndef find_orders(conn, customer_id:\n```"          # always broken
        if "DEAD_CODE" in first:
            return "```python\n# DELETE\n```"
        return "I am not sure."                                                   # never submits
    return "{}"


class _FakeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        srv = self.server
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        srv.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                             "body": body})
        if srv.fail_with:
            self.send_response(srv.fail_with); self.end_headers()
            self.wfile.write(b'{"error": {"message": "nope"}}'); return
        if self.path.endswith("/messages"):
            text = brain(body["system"], body["messages"])
            out = {"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                   "content": [{"type": "thinking", "thinking": "hmm", "signature": "sig"},
                               {"type": "text", "text": text}],
                   "stop_reason": "end_turn", "usage": {"input_tokens": 100, "output_tokens": 20}}
        else:
            msgs = body["messages"]
            text = brain(msgs[0]["content"], msgs[1:])
            out = {"id": "c1", "object": "chat.completion", "model": body["model"],
                   "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                "finish_reason": "stop"}],
                   "usage": {"prompt_tokens": 100, "completion_tokens": 20}}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def fake_llm_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeHandler)
    srv.requests, srv.fail_with = [], None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    yield srv
    srv.shutdown()
