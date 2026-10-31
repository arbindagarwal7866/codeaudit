"""Local web UI (standard library only):  python -m codeaudit serve  ->  http://127.0.0.1:8765

  - paste a local folder or a GitHub URL, choose the AI provider, run
  - live progress log while the 7 stages run
  - open the full report, then Accept (apply to your files), make a PR branch, or Reject each fix
Listens on 127.0.0.1 only.
"""
from __future__ import annotations
import json
import re
import subprocess
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .agents.llm import available_providers, detect_provider
from .pipeline import AuditOptions, run
from .pr import create_branch_commit, is_git_root, pr_text, prepare_sandbox, push_and_open_pr, PRError

JOBS: dict[str, dict] = {}
LOCK = threading.Lock()
OUT_ROOT = Path("audit_out") / "web"


def _start_job(params: dict) -> str:
    jid = time.strftime("%H%M%S") + "-" + uuid.uuid4().hex[:4]
    out = (OUT_ROOT / jid).resolve()
    job = {"id": jid, "status": "running", "log": [], "params": params, "out": str(out),
           "decisions": {}, "started": time.time()}
    with LOCK:
        JOBS[jid] = job

    def progress(msg):
        with LOCK:
            job["log"].append(msg)

    def work():
        try:
            opts = AuditOptions(
                repo=params["repo"], out_dir=str(out), provider=params.get("provider") or "auto",
                model=params.get("model") or None, base_url=params.get("base_url") or None,
                top_k=int(params.get("top_k") or 15), refactor_k=int(params.get("refactor_k") or 8),
                run_tests=bool(params.get("run_tests")), mode=params.get("mode") or "auto",
                labels=params.get("labels") or None)
            data = run(opts, progress=progress)
            with LOCK:
                job["data"] = data
                job["status"] = "done"
        except Exception as e:
            with LOCK:
                job["status"] = "error"
                job["error"] = f"{type(e).__name__}: {e}"
                job["log"].append(traceback.format_exc().splitlines()[-1])

    threading.Thread(target=work, daemon=True).start()
    return jid


def _job_view(job: dict) -> dict:
    view = {k: job[k] for k in ("id", "status", "log", "params", "decisions")}
    view["error"] = job.get("error")
    d = job.get("data")
    if d:
        view["summary"] = d["summary"]
        view["evaluation"] = d.get("evaluation")
        view["patches"] = [
            {"id": r["finding"]["id"], "rule": r["finding"]["rule"], "category": r["finding"]["category"],
             "message": r["finding"]["message"], "file": r["finding"]["file"], "by": r["refactor"]["by"],
             "description": r["refactor"]["validation"].get("description", ""),
             "checks": r["refactor"]["validation"]["checks"], "diff": r["refactor"]["validation"]["diff"]}
            for r in d["results"] if r.get("refactor", {}).get("ok")]
    return view


def _apply(job: dict, fid: str) -> dict:
    repo = job["data"]["summary"]["repo"]
    patch = (Path(job["out"]) / "patches" / f"{fid}.diff").resolve()
    r = subprocess.run(["git", "apply", str(patch)], cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        return {"ok": False, "message": (r.stderr or r.stdout).strip()[:300] or "git apply failed"}
    return {"ok": True, "message": f"applied to {repo}"}


def _pr(job: dict, fid: str, push: bool) -> dict:
    data = job["data"]
    repo = data["summary"]["repo"]
    if not is_git_root(repo):
        sb = Path(job["out"]) / "pr_sandbox"
        repo = str(sb) if (sb / ".git").exists() else prepare_sandbox(repo, str(sb))
    res = next(r for r in data["results"] if r["finding"]["id"] == fid)
    title, body = pr_text(res)
    branch = f"codeaudit/{res['finding']['rule'].lower().replace('_', '-')}-{fid.lower()}"
    patch = (Path(job["out"]) / "patches" / f"{fid}.diff").resolve()
    sha = create_branch_commit(repo, branch, str(patch), f"{title}\n\n{body}")
    out = {"ok": True, "message": f"branch {branch} @ {sha} in {repo}"}
    if push:
        out["message"] += " · PR: " + push_and_open_pr(repo, branch, title, body)
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (
            json.dumps(body, default=str).encode() if ctype == "application/json" else body.encode())
        self.send_response(code)
        self.send_header("content-type", ctype + ("; charset=utf-8" if "text" in ctype or "json" in ctype else ""))
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("content-length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, INDEX_HTML, "text/html")
        if p == "/api/providers":
            return self._send(200, {"providers": available_providers(), "auto": detect_provider()})
        if p == "/api/jobs":
            with LOCK:
                return self._send(200, [{"id": j["id"], "status": j["status"], "repo": j["params"]["repo"]}
                                        for j in JOBS.values()])
        m = re.fullmatch(r"/api/jobs/([\w-]+)", p)
        if m and m.group(1) in JOBS:
            with LOCK:
                return self._send(200, _job_view(JOBS[m.group(1)]))
        m = re.fullmatch(r"/jobs/([\w-]+)/report", p)
        if m and m.group(1) in JOBS:
            f = Path(JOBS[m.group(1)]["out"]) / "report.html"
            if f.exists():
                return self._send(200, f.read_bytes(), "text/html")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = self.path
        try:
            body = self._body()
            if p == "/api/audit":
                if not str(body.get("repo", "")).strip():
                    return self._send(400, {"error": "repo is required"})
                return self._send(200, {"job": _start_job(body)})
            m = re.fullmatch(r"/api/jobs/([\w-]+)/(apply|pr|reject)", p)
            if m and m.group(1) in JOBS:
                job, action, fid = JOBS[m.group(1)], m.group(2), body.get("finding")
                if job["status"] != "done":
                    return self._send(409, {"error": "job not finished"})
                if action == "reject":
                    res = {"ok": True, "message": "rejected"}
                elif action == "apply":
                    res = _apply(job, fid)
                else:
                    res = _pr(job, fid, bool(body.get("push")))
                if res["ok"]:
                    job["decisions"][fid] = {"action": action, "message": res["message"]}
                return self._send(200, res)
            return self._send(404, {"error": "not found"})
        except (PRError, StopIteration, ValueError) as e:
            return self._send(400, {"ok": False, "message": str(e)})
        except Exception as e:
            return self._send(500, {"ok": False, "message": f"{type(e).__name__}: {e}"})


def serve(port: int = 8765, open_browser: bool = False):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"CodeAudit web UI on {url}  (Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


INDEX_HTML = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>CodeAudit</title>
<style>
:root{--bg:#f6f6f3;--card:#fff;--ink:#1c1c1e;--mute:#6b6b72;--line:#e2e2dd;--acc:#2f5bd3;--ok:#1e7f46;
--bad:#c2312f;--add:#e5f5ea;--del:#fbe9e8;--chip:#efefea}
@media (prefers-color-scheme:dark){:root{--bg:#131315;--card:#1c1c1f;--ink:#ececef;--mute:#9a9aa3;--line:#2e2e33;
--acc:#86a2ff;--ok:#4cc27c;--bad:#ff6b66;--add:#13301e;--del:#3a1919;--chip:#26262b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px 60px}h1{margin:0;font-size:26px}h2{font-size:17px;margin:26px 0 10px}
.mute{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
form{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;align-items:end}
label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--mute)}
input,select{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.wide{grid-column:1/-1}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{font:inherit;border:0;border-radius:8px;padding:9px 16px;background:var(--ink);color:var(--bg);cursor:pointer}
button.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}button:disabled{opacity:.5;cursor:wait}
#log{font:12.5px/1.5 ui-monospace,Consolas,monospace;background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:12px;max-height:280px;overflow:auto;white-space:pre-wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.cards div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px}.cards b{display:block;font-size:22px}
.patch{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin:10px 0}
pre{overflow-x:auto;font:12.5px/1.45 ui-monospace,Consolas,monospace;background:var(--bg);border-radius:8px;padding:10px}
.ln{display:block}.add{background:var(--add)}.del{background:var(--del)}.ok{color:var(--ok)}.bad{color:var(--bad)}
iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.status{font-size:13px;padding:2px 10px;border-radius:999px;border:1px solid currentColor}
</style></head><body><main>
<h1>CodeAudit</h1><p class=mute>Autonomous codebase auditor &amp; refactoring agent — repository-scale analysis with graph context for the AI.</p>
<div class=card><form id=f>
<label class=wide>Repository — local folder or GitHub URL<input name=repo placeholder="examples/shopkart  or  https://github.com/owner/repo" required></label>
<label>AI provider<select name=provider id=prov></select></label>
<label>Model (optional)<input name=model placeholder="provider default"></label>
<label>Base URL (OpenAI-compatible, optional)<input name=base_url placeholder="https://.../v1"></label>
<label>Findings to analyse (top-K)<input name=top_k type=number value=15 min=1></label>
<label>Max patches<input name=refactor_k type=number value=8 min=0></label>
<label>Dead-code mode<select name=mode><option>auto</option><option>app</option><option>library</option></select></label>
<label>Labels CSV for evaluation (optional)<input name=labels placeholder="examples/shopkart_labels.csv"></label>
<label class=row style="flex-direction:row"><input type=checkbox name=run_tests> run the project's tests on every patch</label>
<div class=row><button id=go>Run audit</button><span id=st class=mute></span></div>
</form></div>
<h2>Progress</h2><div id=log class=mute>Waiting for a repository…</div>
<div id=res></div>
<script>
const $=s=>document.querySelector(s);let job=null,timer=null;
fetch('/api/providers').then(r=>r.json()).then(d=>{const s=$('#prov');
 s.innerHTML='<option value=auto>auto (detected: '+d.auto+')</option>'+d.providers.map(p=>
 `<option value="${p.name}" ${p.available?'':'class=mute'}>${p.name} — ${p.note}</option>`).join('');});
$('#f').onsubmit=async ev=>{ev.preventDefault();const fd=new FormData(ev.target),body=Object.fromEntries(fd);
 body.run_tests=fd.get('run_tests')==='on';$('#go').disabled=true;$('#res').innerHTML='';$('#log').textContent='Starting…';
 const r=await fetch('/api/audit',{method:'POST',body:JSON.stringify(body)}).then(r=>r.json());
 if(r.error){$('#log').textContent=r.error;$('#go').disabled=false;return}job=r.job;timer=setInterval(poll,700);};
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function diff(d){return '<pre>'+d.split('\n').map(l=>{const c=l.startsWith('+')&&!l.startsWith('+++')?'add':
 l.startsWith('-')&&!l.startsWith('---')?'del':'';return `<span class="ln ${c}">${esc(l)||' '}</span>`}).join('')+'</pre>'}
async function poll(){const j=await fetch('/api/jobs/'+job).then(r=>r.json());$('#log').textContent=j.log.join('\n');
 $('#log').scrollTop=1e9;$('#st').innerHTML=`<span class=status>${j.status}</span>`;
 if(j.status==='running')return;clearInterval(timer);$('#go').disabled=false;
 if(j.status==='error'){$('#res').innerHTML=`<p class=bad>${esc(j.error)}</p>`;return}render(j);}
function render(j){const s=j.summary;let h=`<h2>Result</h2><div class=cards>
 <div><b>${s.graph.files}</b><span class=mute>files</span></div><div><b>${s.findings_total}</b><span class=mute>static findings</span></div>
 <div><b>${s.confirmed}</b><span class=mute>confirmed real</span></div><div><b>${s.dismissed}</b><span class=mute>dismissed false alarms</span></div>
 <div><b>${s.patches}</b><span class=mute>validated patches</span></div><div><b style="font-size:15px">${esc(s.llm)}</b><span class=mute>agents</span></div></div>`;
 if(j.evaluation&&j.evaluation.before_triage){const b=j.evaluation.before_triage,a=j.evaluation.after_triage;
  h+=`<p>Precision <b>${b.precision} → ${a.precision}</b> · false alarms <b>${b.fp} → ${a.fp}</b> · recall <b>${b.recall} → ${a.recall}</b></p>`}
 h+=`<h2>Validated fixes — review each one</h2>`;
 if(!j.patches.length)h+='<p class=mute>No validated patches.</p>';
 for(const p of j.patches){const d=j.decisions[p.id];h+=`<div class=patch id=p-${p.id}><div class=row><b>${p.id}</b><code>${p.rule}</code>
  <span class=mute>${esc(p.file)} · by ${esc(p.by)}</span></div><p>${esc(p.message)}</p><p class=mute>${esc(p.description)}</p>
  <p>${p.checks.map(c=>`<span class=${c.passed?'ok':'bad'}>${c.passed?'✓':'✗'} ${esc(c.name)}</span>`).join(' &nbsp; ')}</p>${diff(p.diff)}
  <div class=row><button onclick="act('${p.id}','apply')">Accept &amp; apply</button><button class=ghost onclick="act('${p.id}','pr')">Create PR branch</button>
  <button class=ghost onclick="act('${p.id}','reject')">Reject</button><span class=mute id=m-${p.id}>${d?esc(d.action+': '+d.message):''}</span></div></div>`}
 h+=`<h2>Full report</h2><iframe src="/jobs/${j.id}/report"></iframe>`;$('#res').innerHTML=h;}
async function act(fid,action){$('#m-'+fid).textContent='…';const r=await fetch(`/api/jobs/${job}/${action}`,{method:'POST',
 body:JSON.stringify({finding:fid})}).then(r=>r.json());$('#m-'+fid).innerHTML=`<span class=${r.ok?'ok':'bad'}>${esc(r.message)}</span>`;}
</script></main></body></html>"""
