"""Stage 7: a single self-contained HTML report (works offline, no server, no CDN)."""
from __future__ import annotations
import json
import math
import random
from html import escape as e
from pathlib import Path

CAT_LABEL = {"security": "Security", "architecture": "Architecture", "dead_code": "Dead code", "smell": "Code smell"}

CSS = """
:root{--bg:#f6f6f3;--card:#fff;--ink:#1c1c1e;--mute:#6b6b72;--line:#e2e2dd;--acc:#2f5bd3;
--ok:#1e7f46;--warn:#a86a12;--bad:#c2312f;--add:#e5f5ea;--del:#fbe9e8;--chip:#efefea;
--security:#c2312f;--architecture:#6a4bc4;--dead_code:#5f6b7a;--smell:#a86a12}
@media (prefers-color-scheme:dark){:root{--bg:#131315;--card:#1c1c1f;--ink:#ececef;--mute:#9a9aa3;
--line:#2e2e33;--acc:#86a2ff;--add:#13301e;--del:#3a1919;--chip:#26262b;--ok:#4cc27c;--bad:#ff6b66;
--security:#ff6b66;--architecture:#a990ff;--dead_code:#9aa7b8;--smell:#e3a548;--warn:#e3a548}}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--ink)}main{max-width:1180px;margin:0 auto;padding:28px 16px 70px}
h1{font-size:27px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:18px;margin:34px 0 12px}
.mute{color:var(--mute)}code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
code{font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 14px}
.card b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.card span{font-size:13px}
.stages{display:flex;flex-wrap:wrap;gap:7px}.st{border:1px solid var(--ok);color:var(--ok);border-radius:999px;
padding:3px 11px;font-size:13px;background:var(--card)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 9px;
border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--mute);font-size:13px}
tr.row{cursor:pointer}tr.row:hover td{background:var(--chip)}tr.hidden{display:none}
.pill{font-size:12px;padding:1px 8px;border-radius:999px;white-space:nowrap;border:1px solid currentColor;display:inline-block}
.real{color:var(--bad)}.fa{color:var(--ok)}.none{color:var(--mute)}
.cat{font-size:12px;font-weight:600}.cat.security{color:var(--security)}.cat.architecture{color:var(--architecture)}
.cat.dead_code{color:var(--dead_code)}.cat.smell{color:var(--smell)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}.filters button{font:inherit;font-size:13px;
border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:4px 12px;cursor:pointer}
.filters button.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.detail td{background:var(--bg);padding:14px}.detail h4{margin:12px 0 4px;font-size:14px}
.detail ul{margin:4px 0 4px 18px;padding:0}pre{overflow-x:auto;font-size:12.5px;line-height:1.45;
background:var(--card);border:1px solid var(--line);padding:10px;border-radius:8px;margin:6px 0}
.ln{display:block}.add{background:var(--add)}.del{background:var(--del)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.graph svg{width:100%;height:auto;display:block}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;margin-top:8px}.lg{display:inline-block;width:22px;
height:0;border-top:2px solid;vertical-align:middle;margin-right:6px}
.eval td:not(:first-child),.eval th:not(:first-child){text-align:right;font-variant-numeric:tabular-nums}
.explain{font-size:14px;margin:10px 0 0;padding-left:18px}
"""

JS = """
let cat='all',showFP=false;
function apply(){document.querySelectorAll('tr.row').forEach(r=>{
 const okc=cat==='all'||r.dataset.cat===cat, okv=showFP||r.dataset.v!=='FALSE_POSITIVE';
 r.classList.toggle('hidden',!(okc&&okv)); const d=document.getElementById('d-'+r.dataset.id);
 if(d&&!(okc&&okv))d.classList.add('hidden');});}
document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>{cat=b.dataset.filter;
 document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('on',x===b));apply();});
const fp=document.getElementById('fp');if(fp)fp.onclick=()=>{showFP=!showFP;fp.classList.toggle('on',showFP);apply();};
document.querySelectorAll('tr.row').forEach(r=>r.onclick=()=>{document.getElementById('d-'+r.dataset.id).classList.toggle('hidden');});
apply();
"""


# ------------------------------------------------------------------ graph layout
def _layout(nodes: list[str], edges: list[tuple[str, str]], w=960, h=520, iters=300) -> dict:
    """Fruchterman-Reingold force layout, deterministic (seeded)."""
    rnd = random.Random(42)
    n = max(1, len(nodes))
    pos = {v: [w / 2 + 200 * math.cos(2 * math.pi * i / n) + rnd.uniform(-5, 5),
               h / 2 + 160 * math.sin(2 * math.pi * i / n) + rnd.uniform(-5, 5)] for i, v in enumerate(nodes)}
    k = 0.9 * math.sqrt(w * h / n)
    temp = w / 8
    for _ in range(iters):
        disp = {v: [0.0, 0.0] for v in nodes}
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = max(0.01, math.hypot(dx, dy))
                f = k * k / d
                disp[a][0] += dx / d * f; disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f; disp[b][1] -= dy / d * f
        for a, b in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = max(0.01, math.hypot(dx, dy))
            f = d * d / k
            disp[a][0] -= dx / d * f; disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f; disp[b][1] += dy / d * f
        for v in nodes:
            dx, dy = disp[v]
            d = max(0.01, math.hypot(dx, dy))
            pos[v][0] += dx / d * min(d, temp)
            pos[v][1] += dy / d * min(d, temp)
            pos[v][0] += (w / 2 - pos[v][0]) * 0.01        # gentle gravity
            pos[v][1] += (h / 2 - pos[v][1]) * 0.01
        temp = max(1.0, temp * 0.97)
    xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    sx = (w - 160) / max(1, maxx - minx)
    sy = (h - 80) / max(1, maxy - miny)
    return {v: (80 + (p[0] - minx) * sx, 40 + (p[1] - miny) * sy) for v, p in pos.items()}


def _graph_svg(mg: dict, unused: set[str]) -> str:
    nodes = [n for n in mg["nodes"] if not n["test"]]
    if len(nodes) > 70:
        nodes = sorted(nodes, key=lambda n: -n["findings"] - 5 * n["pagerank"])[:70]
    ids = {n["id"] for n in nodes}
    edges = [x for x in mg["edges"] if x["src"] in ids and x["dst"] in ids]
    if not nodes:
        return "<p class=mute>No modules.</p>"
    pos = _layout([n["id"] for n in nodes], [(x["src"], x["dst"]) for x in edges])
    prefix = _common_prefix([n["id"] for n in nodes])
    out = ['<svg viewBox="0 0 960 520" role="img" aria-label="module dependency graph">',
           '<defs><marker id="ar" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0L10,5L0,10z" fill="var(--mute)"/></marker>'
           '<marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0L10,5L0,10z" fill="var(--bad)"/></marker></defs>']
    radius = {n["id"]: 7 + min(14, math.sqrt(n["loc"]) / 2) for n in nodes}
    pairs = {(x["src"], x["dst"]) for x in edges}
    for x in sorted(edges, key=lambda x: x["cycle"]):
        (x1, y1), (x2, y2) = pos[x["src"]], pos[x["dst"]]
        d = max(1, math.hypot(x2 - x1, y2 - y1))
        bend = 28 if (x["dst"], x["src"]) in pairs else 0       # two-way edges curve apart
        nx_, ny_ = -(y2 - y1) / d, (x2 - x1) / d
        cx, cy = (x1 + x2) / 2 + nx_ * bend, (y1 + y2) / 2 + ny_ * bend
        dd = max(1, math.hypot(x2 - cx, y2 - cy))
        r2 = radius[x["dst"]] + 3
        ex, ey = x2 - (x2 - cx) / dd * r2, y2 - (y2 - cy) / dd * r2
        col = "var(--bad)" if x["cycle"] else "var(--mute)"
        dash = ' stroke-dasharray="4 4"' if x["lazy"] else ""
        width = 2.4 if x["cycle"] else 1
        op = 1 if x["cycle"] else 0.45
        out.append(f'<path d="M{x1:.1f},{y1:.1f} Q{cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" fill="none" stroke="{col}" '
                   f'stroke-width="{width}" opacity="{op}"{dash} marker-end="url(#{"arr" if x["cycle"] else "ar"})"/>')
    for n in nodes:
        x, y = pos[n["id"]]
        fill = "var(--bad)" if n["findings"] >= 3 else "var(--warn)" if n["findings"] else "var(--ok)"
        dash = ' stroke-dasharray="4 3" stroke="var(--ink)"' if n["id"] in unused else ' stroke="var(--card)"'
        label = n["id"][len(prefix):] or n["id"]
        out.append(f'<g><title>{e(n["id"])}: {n["loc"]} lines, {n["findings"]} finding(s), centrality {n["pagerank"]}</title>'
                   f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius[n["id"]]:.1f}" fill="{fill}" '
                   f'fill-opacity="{".35" if n["id"] in unused else ".85"}" stroke-width="1.5"{dash}/>'
                   f'<text x="{x:.1f}" y="{y - radius[n["id"]] - 5:.1f}" text-anchor="middle" font-size="12" '
                   f'fill="var(--ink)" style="paint-order:stroke;stroke:var(--card);stroke-width:3px">{e(label)}</text></g>')
    out.append("</svg>")
    return "".join(out)


def _common_prefix(ids: list[str]) -> str:
    parts = [i.split(".") for i in ids]
    if len(parts) < 2:
        return ""
    pre = []
    for col in zip(*parts):
        if len(set(col)) == 1:
            pre.append(col[0])
        else:
            break
    if pre and all(len(p) > len(pre) for p in parts):
        return ".".join(pre) + "."
    return ""


# ------------------------------------------------------------------ helpers
def _diff_html(diff: str) -> str:
    rows = []
    for line in diff.splitlines():
        cls = "add" if line.startswith("+") and not line.startswith("+++") else \
              "del" if line.startswith("-") and not line.startswith("---") else ""
        rows.append(f'<span class="ln {cls}">{e(line) or " "}</span>')
    return "<pre>" + "".join(rows) + "</pre>"


def _verdict_pill(v):
    if v == "TRUE_POSITIVE":
        return "<span class='pill real'>real issue</span>"
    if v == "FALSE_POSITIVE":
        return "<span class='pill fa'>false alarm</span>"
    return "<span class='pill none'>not triaged</span>"


def _detail(r: dict) -> str:
    f, h = r["finding"], []
    h.append(f"<p><b>{e(f['message'])}</b></p>")
    h.append(f"<p class=mute>Rule <code>{f['rule']}</code>{' · ' + f['cwe'] if f.get('cwe') else ''} · "
             f"severity {f['severity']} · static confidence {f['confidence']} · priority {f['priority']} · "
             f"<code>{e(f['file'])}:{f['start_line']}</code></p>")
    ctx = r.get("context")
    if ctx:
        h.append(f"<h4>What the AI was given (graph context, ~{ctx['approx_tokens']} tokens — not the whole repo)</h4><ul>"
                 + "".join(f"<li>{e(x)}</li>" for x in ctx["facts"]) + "</ul>")
        if ctx["callers"] or ctx["callees"]:
            h.append(f"<p class=mute>Code included: callers {e(', '.join(ctx['callers']) or '—')}; "
                     f"callees {e(', '.join(ctx['callees']) or '—')}. Full pack: <code>context/{f['id']}.txt</code></p>")
    t = r.get("triage")
    if t:
        h.append(f"<h4>Triage agent</h4><p>{_verdict_pill(t['verdict'])} confidence {t['confidence']:.2f} — "
                 f"{e(t['reason'])} <span class=mute>({e(t.get('mode', ''))})</span></p>")
    a = r.get("analysis")
    if a:
        h.append("<h4>Analyst agent</h4>"
                 f"<p><b>Summary:</b> {e(str(a.get('summary', '')))}<br><b>Root cause:</b> {e(str(a.get('root_cause', '')))}"
                 f"<br><b>Impact:</b> {e(str(a.get('impact', '')))}</p>"
                 "<b>Fix plan</b><ul>" + "".join(f"<li>{e(str(x))}</li>" for x in a.get("fix_plan", [])) + "</ul>")
    rf = r.get("refactor")
    if rf:
        status = "<span class=ok>✓ validated patch</span>" if rf.get("ok") else "<span class=bad>✗ no valid patch</span>"
        h.append(f"<h4>Refactorer + Validator</h4><p>{status} · produced by <b>{e(rf.get('by', ''))}</b>"
                 + (f" · {e(rf['error'])}" if rf.get("error") else "") + "</p>")
        if rf.get("transcript"):
            h.append("<ul>" + "".join(f"<li>step {s['step']}: <code>{e(s['action'])}</code> → {e(str(s['result']))}</li>"
                                      for s in rf["transcript"]) + "</ul>")
        v = rf.get("validation")
        if v:
            h.append("<ul>" + "".join(f"<li class={'ok' if c['passed'] else 'bad'}>{'✓' if c['passed'] else '✗'} "
                                      f"{e(c['name'])} <span class=mute>{e(c['detail'])}</span></li>"
                                      for c in v["checks"]) + "</ul>")
            if v.get("description"):
                h.append(f"<p class=mute>{e(v['description'])}</p>")
            if v.get("diff"):
                h.append(_diff_html(v["diff"]))
        for n in rf.get("notes", []) or []:
            h.append(f"<p class=mute>Note: {e(n)}</p>")
    ev = {k: v for k, v in f["evidence"].items() if k not in ("edges", "users", "taint_path", "dependents", "dependencies")}
    h.append(f"<details><summary class=mute>raw evidence</summary><pre>{e(json.dumps(ev, indent=1, default=str))}</pre></details>")
    return "".join(h)


def _evaluation(ev: dict) -> str:
    b, a = ev["before_triage"], ev["after_triage"]
    rows = [("Precision", b["precision"], a["precision"]), ("Recall", b["recall"], a["recall"]),
            ("F1 score", b["f1"], a["f1"]), ("Real issues reported (TP)", b["tp"], a["tp"]),
            ("False alarms reported (FP)", b["fp"], a["fp"]), ("Real issues missed (FN)", b["fn"], a["fn"])]
    h = ["<div class=panel><table class=eval><tr><th>Metric</th><th>Static rules only</th>"
         f"<th>After triage ({e(ev['triage_mode'])})</th></tr>"]
    for name, x, y in rows:
        h.append(f"<tr><td>{name}</td><td>{x}</td><td><b>{y}</b></td></tr>")
    h.append("</table><ul class=explain>"
             f"<li><b>Precision {b['precision']} → {a['precision']}</b>: of everything shown to the developer, "
             f"the share that is a real problem.</li>"
             f"<li><b>False alarms {b['fp']} → {a['fp']}</b>: noise removed by the triage agent "
             f"({ev['false_positives_removed']} removed).</li>"
             f"<li><b>Recall {b['recall']} → {a['recall']}</b>: share of all real issues that are reported. "
             f"{ev['real_issues_wrongly_dismissed']} real issue(s) wrongly dismissed by triage; "
             f"{ev['missed_by_rules']} never found by the static rules.</li></ul>")
    if ev.get("missed"):
        h.append(f"<p class=mute>Missed by the rules: {e(', '.join(ev['missed']))}</p>")
    if ev.get("triage_mistakes"):
        h.append("<p class=mute>Triage mistakes: " + e("; ".join(f"{m['key']} (label {m['label']})"
                                                             for m in ev["triage_mistakes"])) + "</p>")
    h.append("</div>")
    return "".join(h)


# ------------------------------------------------------------------ page
def write_html(data: dict, path: Path):
    s, results = data["summary"], data["results"]
    st = s["graph"]
    cats = {}
    for r in results:
        cats[r["finding"]["category"]] = cats.get(r["finding"]["category"], 0) + 1
    h = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>CodeAudit Report</title><style>{CSS}</style></head><body><main>",
         f"<h1>CodeAudit report</h1><div class=mute>{e(s['source'])} · {s['created']} · dead-code mode "
         f"<b>{e(s['mode'])}</b> · agents: <b>{e(s['llm'])}</b> · tests: {e(s['tests'])}</div>",
         "<h2>Pipeline</h2><div class=stages>"]
    for name in ["1 Ingest", "2 Parse (AST)", "3 Dependency graph", "4 Static rules", "5 Ranking",
                 "6a Triage agent", "6b Analyst agent", "6c Refactorer agent", "6d Validator", "7 Report",
                 "PR export"]:
        h.append(f"<span class=st>✓ {e(name)}</span>")
    h.append("</div>")
    usage = s.get("llm_usage") or {}
    cards = [("Python files", st["files"]), ("Symbols", sum(st["nodes"].values())),
             ("Graph edges", sum(st["edges"].values())), ("Static findings", s["findings_total"]),
             ("Reviewed by triage", s["triaged"]), ("Confirmed real", s["confirmed"]),
             ("Dismissed as false alarm", s["dismissed"]), ("Validated patches", s["patches"])]
    if usage:
        cards.append(("LLM calls (cached)", f"{usage['api_calls']} ({usage['cache_hits']})"))
        cards.append(("Tokens in / out", f"{usage['input_tokens']} / {usage['output_tokens']}"))
    h.append("<h2>Summary</h2><div class=cards>" + "".join(
        f"<div class=card><b>{v}</b><span class=mute>{e(k)}</span></div>" for k, v in cards) + "</div>")
    if data.get("evaluation") and "before_triage" in data["evaluation"]:
        h.append("<h2>Evaluation against ground truth</h2>" + _evaluation(data["evaluation"]))
    h.append("<h2>Module dependency graph</h2><div class='panel graph'>"
             + _graph_svg(data["module_graph"], set(s.get("unused_modules", [])))
             + "<div class=legend><span><span class=lg style='border-color:var(--bad)'></span>import cycle</span>"
               "<span><span class=lg style='border-color:var(--mute)'></span>import</span>"
               "<span><span class=lg style='border-color:var(--mute);border-top-style:dashed'></span>lazy import (inside a function)</span>"
               "<span class=mute>circle size = lines of code · colour = number of findings · dashed circle = unused module</span></div></div>")
    h.append("<h2>Findings</h2><div class=filters><button class=on data-filter=all>All "
             f"({len(results)})</button>" + "".join(
                 f"<button data-filter={c}>{CAT_LABEL.get(c, c)} ({n})</button>" for c, n in cats.items())
             + "<button id=fp>Show false alarms</button></div>")
    h.append("<div class=panel><table><tr><th>ID</th><th>Category</th><th>Rule</th><th>Where</th>"
             "<th>Finding</th><th>Verdict</th><th>Patch</th></tr>")
    for r in results:
        f = r["finding"]
        v = r.get("triage", {}).get("verdict")
        patch = "✓" if r.get("refactor", {}).get("ok") else ""
        h.append(f"<tr class=row data-id={f['id']} data-cat={f['category']} data-v={v or 'none'}>"
                 f"<td>{f['id']}</td><td><span class='cat {f['category']}'>{CAT_LABEL.get(f['category'], '')}</span></td>"
                 f"<td><code>{f['rule']}</code></td><td><code>{e(f['file'])}:{f['start_line']}</code></td>"
                 f"<td>{e(f['message'])}</td><td>{_verdict_pill(v)}</td><td class=ok>{patch}</td></tr>"
                 f"<tr class='detail hidden' id=d-{f['id']}><td colspan=7>{_detail(r)}</td></tr>")
    h.append("</table></div>")
    h.append(f"<p class=mute style='margin-top:26px'>Timings (s): {e(str(s['timings_sec']))} · "
             f"call resolution {st['call_resolution_rate']} · entry modules: {e(', '.join(s['entry_modules'][:8]))}</p>")
    h.append(f"<script>{JS}</script></main></body></html>")
    Path(path).write_text("".join(h), encoding="utf-8")
