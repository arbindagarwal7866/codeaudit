"""Runs all stages end to end. Used by the CLI and the web UI.

  1 ingest      local folder or GitHub URL
  2 parse       AST -> symbols
  3 graph       dependency graph (symbols + modules), PageRank, blast radius
  4 rules       architecture / security / dead code / smells  (deterministic)
  5 rank        priority -> top-K gate
  6 agents      Triage -> Analyst -> Refactorer <-> Validator   (LLM or offline)
  7 report      report.html, results.json, patches/*.diff, context/*.txt
"""
from __future__ import annotations
import csv
import json
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from .ingest import resolve_source
from .graph import CodeGraph
from .rules import run_rules
from .rank import rank
from .context import build_context
from .models import to_dict
from .agents.llm import LLM, LLMError
from .agents import triage, analyze, refactor, validate
from .agents.validator import default_test_cmd, run_tests, copy_repo
from .agents.analyst import AUTO_RULES
from . import report


@dataclass
class AuditOptions:
    repo: str
    out_dir: str = "audit_out"
    provider: str = "auto"          # auto | anthropic | openai | gemini | groq | openrouter | ollama | offline
    model: str | None = None
    smart_model: str | None = None
    base_url: str | None = None
    triage_k: int = 40              # findings the Triage agent reviews
    top_k: int = 15                 # confirmed findings that get Analyst + Refactorer
    refactor_k: int = 6             # max validated patches
    run_tests: bool = False
    test_cmd: str | None = None
    mode: str = "auto"              # dead-code mode: auto | app | library
    budget_chars: int = 12000       # context budget per finding (~3k tokens)
    labels: str | None = None       # ground-truth CSV for evaluation
    use_cache: bool = True


def run(opts: AuditOptions, progress=None, llm: LLM | None = None) -> dict:
    log = progress or (lambda m: print(f"[codeaudit] {m}", flush=True))
    out = Path(opts.out_dir)
    for sub in ("patches", "context"):
        (out / sub).mkdir(parents=True, exist_ok=True)
        for old in (out / sub).glob("*"):
            old.unlink()
    t0, timings = time.time(), {}

    # 1-3 ingest, parse, graph
    repo = resolve_source(opts.repo, log=log)
    log(f"[1/7] ingesting {repo}")
    cg = CodeGraph.build(repo)
    cg.save(str(out / "graph.json"))
    st = cg.stats()
    log(f"[2/7] parsed {st['files']} files ({st['test_files']} test files), {sum(st['nodes'].values())} symbols")
    if cg.parse_errors:
        bad = sorted(cg.parse_errors)
        log(f"      skipped {len(bad)} file(s) that are not valid Python 3: {', '.join(bad[:5])}"
            + (" ..." if len(bad) > 5 else ""))
    if not st["files"]:
        log("      WARNING: no Python files found. CodeAudit audits Python (.py) code only")
    log(f"[3/7] dependency graph: {sum(st['edges'].values())} symbol edges, {st['module_edges']} module edges")
    timings["graph"] = time.time() - t0

    # 4-5 rules, ranking
    t = time.time()
    findings, lv = run_rules(cg, mode=opts.mode)
    findings = rank(cg, findings)
    by_cat = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    log(f"[4/7] static rules: {len(findings)} candidates {by_cat} (mode: {lv.mode})")
    log(f"[5/7] ranked by severity x confidence x centrality x blast radius")
    timings["rules+rank"] = time.time() - t
    _write_label_template(out / "labels_template.csv", findings)
    baseline_keys = {f.key for f in findings}

    # 6 agents
    t = time.time()
    if llm is None:
        try:
            llm = LLM(opts.provider, opts.model, opts.smart_model, opts.base_url, use_cache=opts.use_cache)
        except LLMError as e:
            log(f"LLM unavailable ({e}); using offline heuristic agents")
            llm = LLM("offline")
    log(f"[6/7] agents running with: {llm.label}")

    test_cmd, test_note = None, "not requested"
    if opts.run_tests:
        test_cmd = opts.test_cmd or default_test_cmd(repo)
        if not test_cmd:
            test_note = "no tests found"
        else:
            with tempfile.TemporaryDirectory(prefix="codeaudit_base_") as tmp:
                ok, tail = run_tests(str(copy_repo(cg, tmp)), test_cmd)
            test_note = "baseline tests pass" if ok else f"baseline tests FAIL ({tail}); test check disabled"
            if not ok:
                test_cmd = None
        log(f"      tests: {test_note}")

    results = {f.id: {"finding": to_dict(f)} for f in findings}
    patches, confirmed, dismissed = 0, 0, 0
    for i, f in enumerate(findings):
        r = results[f.id]
        if i >= opts.triage_k:
            break
        ctx = build_context(cg, f, lv.entry_symbols, budget_chars=opts.budget_chars)
        (out / "context" / f"{f.id}.txt").write_text(ctx.to_prompt(), encoding="utf-8")
        r["context"] = {"facts": ctx.facts, "approx_tokens": ctx.approx_tokens,
                        "callers": [c["id"] for c in ctx.callers], "callees": [c["id"] for c in ctx.callees]}
        r["triage"] = triage(llm, cg, f, ctx, lv.mode)
        r["finding"]["llm_verdict"] = f.llm_verdict
        if f.llm_verdict != "TRUE_POSITIVE":
            dismissed += 1
            log(f"      {f.id} {f.rule:<24} dismissed: {r['triage']['reason'][:70]}")
            continue
        confirmed += 1
        if confirmed > opts.top_k:
            continue
        r["analysis"] = analyze(llm, cg, f, ctx)
        if patches >= opts.refactor_k or not r["analysis"].get("refactorable") or f.rule not in AUTO_RULES:
            log(f"      {f.id} {f.rule:<24} confirmed (advice only)")
            continue
        vfn = (lambda ch, _f=f: validate(cg, _f, ch, baseline_keys, lv.mode, test_cmd))
        try:
            rf = refactor(llm, cg, f, ctx, r["analysis"], vfn)
        except Exception as e:                                # one bad finding must not kill the run
            rf = {"ok": False, "by": "error", "error": f"{type(e).__name__}: {e}", "transcript": []}
        r["refactor"] = rf
        if rf.get("ok"):
            patches += 1
            (out / "patches" / f"{f.id}.diff").write_text(rf["validation"]["diff"], encoding="utf-8", newline="\n")
            log(f"      {f.id} {f.rule:<24} confirmed -> patch validated ({rf['by']})")
        elif rf.get("by") == "none":
            log(f"      {f.id} {f.rule:<24} confirmed (advice only: no safe automatic fix)")
        else:
            why = rf.get("error") or (rf.get("validation") or {}).get("feedback", "")
            log(f"      {f.id} {f.rule:<24} confirmed -> fix attempted but rejected ({why[:60]})")
    timings["agents"] = time.time() - t

    summary = {
        "repo": cg.repo_root, "source": opts.repo, "mode": lv.mode, "graph": st,
        "llm": llm.label, "llm_usage": None if llm.offline else llm.usage(),
        "findings_total": len(findings), "by_category": by_cat,
        "triaged": min(opts.triage_k, len(findings)), "confirmed": confirmed, "dismissed": dismissed,
        "patches": patches, "tests": test_note,
        "entry_modules": lv.entry_modules, "unused_modules": lv.unused_modules,
        "timings_sec": {k: round(v, 2) for k, v in timings.items()},
        "options": {k: v for k, v in asdict(opts).items() if k not in ("labels",)},
        "created": time.strftime("%Y-%m-%d %H:%M"),
    }
    data = {"summary": summary, "results": list(results.values()), "module_graph": _module_graph(cg, findings)}
    if opts.labels:
        from .evaluate import evaluate_data
        data["evaluation"] = evaluate_data(data, opts.labels)
        log(f"      evaluation: {json.dumps({k: v for k, v in data['evaluation'].items() if k != 'per_category'})[:200]}")
    (out / "results.json").write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    report.write_html(data, out / "report.html")
    log(f"[7/7] report -> {out / 'report.html'}  ({patches} validated patch(es) in {out / 'patches'})")
    return data


def _module_graph(cg: CodeGraph, findings) -> dict:
    cyc = set()
    for f in findings:
        if f.rule == "CYCLIC_DEPENDENCY":
            cyc |= {(e["src"], e["dst"]) for e in f.evidence["edges"]}
    flagged = {}
    for f in findings:
        m = cg.symbols[f.symbol_id].module
        flagged[m] = flagged.get(m, 0) + 1
    nodes = [{"id": m, "file": p, "test": m in cg.test_modules, "loc": cg.symbols[f"{m}:"].length,
              "findings": flagged.get(m, 0), "pagerank": cg.metrics(f"{m}:").get("pagerank", 0)}
             for m, p in cg.modules.items() if f"{m}:" in cg.symbols]
    edges = [{"src": u, "dst": v, "lazy": d.get("lazy", False), "cycle": (u, v) in cyc}
             for u, v, d in cg.mg.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


def _write_label_template(path: Path, findings):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "rule", "file", "line", "message", "label", "note"])
        for f in findings:
            w.writerow([f.key, f.rule, f.file, f.start_line, f.message, "", ""])
