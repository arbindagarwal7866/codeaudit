"""CodeAudit command line.

  python -m codeaudit audit     <folder|github-url> [--provider auto|anthropic|openai|gemini|groq|openrouter|ollama|offline]
                                [--model M] [--base-url URL] [--top-k 15] [--refactor-k 8] [--run-tests]
                                [--labels labels.csv] [--mode auto|app|library] [--out audit_out] [--open]
  python -m codeaudit serve     [--port 8765] [--open]                 local web UI
  python -m codeaudit pr        <audit_out> [--sandbox] [--push] [--only F001,F002]
  python -m codeaudit evaluate  <audit_out/results.json> <labels.csv>
  python -m codeaudit benchmark <folder> <labels.csv> [--provider P ...]  heuristic vs LLM triage
  python -m codeaudit context   <folder> <finding-id|symbol-id>          exactly what the LLM receives
  python -m codeaudit providers                                         which AI providers are configured
  python -m codeaudit graph     <folder> [--out graph.json]             build + save the dependency graph
  python -m codeaudit top       <folder> [--by complexity|loc|fan_in|blast] [-n 15]
"""
from __future__ import annotations
import argparse
import json
import sys
import webbrowser
from pathlib import Path


def _print_eval(ev: dict):
    if "before_triage" not in ev:
        print(json.dumps(ev, indent=2)); return
    b, a = ev["before_triage"], ev["after_triage"]
    print(f"\n{'':28}{'static only':>14}{'after triage':>14}")
    for k in ("precision", "recall", "f1", "tp", "fp", "fn"):
        print(f"{k:28}{b[k]:>14}{a[k]:>14}")
    print(f"\nfalse positives removed: {ev['false_positives_removed']}, "
          f"real issues wrongly dismissed: {ev['real_issues_wrongly_dismissed']}, missed by rules: {ev['missed']}")
    for m in ev.get("triage_mistakes", []):
        print(f"  triage mistake: {m['key']} (label {m['label']}, verdict {m['verdict']})")


def main(argv=None):
    try:
        _main(argv)
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as e:
        sys.exit(f"codeaudit: error: {e}")
    except KeyboardInterrupt:
        sys.exit("\ncodeaudit: stopped")


def _main(argv=None):
    ap = argparse.ArgumentParser(prog="codeaudit", description="Autonomous Codebase Auditor & Refactoring Agent")
    sub = ap.add_subparsers(dest="cmd", required=True)

    au = sub.add_parser("audit", help="run the full pipeline")
    au.add_argument("repo")
    au.add_argument("--out", default="audit_out")
    au.add_argument("--provider", default="auto")
    au.add_argument("--model"); au.add_argument("--smart-model"); au.add_argument("--base-url")
    au.add_argument("--triage-k", type=int, default=40)
    au.add_argument("--top-k", type=int, default=15)
    au.add_argument("--refactor-k", type=int, default=8)
    au.add_argument("--run-tests", action="store_true")
    au.add_argument("--test-cmd")
    au.add_argument("--mode", default="auto", choices=["auto", "app", "library"])
    au.add_argument("--labels")
    au.add_argument("--no-cache", action="store_true")
    au.add_argument("--open", action="store_true", help="open the report in a browser")

    sv = sub.add_parser("serve", help="local web UI")
    sv.add_argument("--port", type=int, default=8765); sv.add_argument("--open", action="store_true")

    pr = sub.add_parser("pr", help="turn validated patches into git branches / GitHub PRs")
    pr.add_argument("audit_dir"); pr.add_argument("--repo")
    pr.add_argument("--sandbox", action="store_true"); pr.add_argument("--push", action="store_true")
    pr.add_argument("--only")

    ev = sub.add_parser("evaluate"); ev.add_argument("results"); ev.add_argument("labels")

    bm = sub.add_parser("benchmark", help="compare triage agents on labelled findings")
    bm.add_argument("repo"); bm.add_argument("labels")
    bm.add_argument("--provider", action="append", default=[])
    bm.add_argument("--model"); bm.add_argument("--base-url"); bm.add_argument("--mode", default="auto")

    cx = sub.add_parser("context", help="print the exact context pack an agent receives")
    cx.add_argument("repo"); cx.add_argument("target"); cx.add_argument("--budget", type=int, default=12000)
    cx.add_argument("--mode", default="auto")

    sub.add_parser("providers")
    gr = sub.add_parser("graph"); gr.add_argument("repo"); gr.add_argument("--out", default="graph.json")
    tp = sub.add_parser("top"); tp.add_argument("repo")
    tp.add_argument("--by", default="complexity"); tp.add_argument("-n", type=int, default=15)

    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):              # Windows consoles: never crash on ✓ or →
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    if a.cmd == "audit":
        from .pipeline import AuditOptions, run
        data = run(AuditOptions(repo=a.repo, out_dir=a.out, provider=a.provider, model=a.model,
                                smart_model=a.smart_model, base_url=a.base_url, triage_k=a.triage_k,
                                top_k=a.top_k, refactor_k=a.refactor_k, run_tests=a.run_tests,
                                test_cmd=a.test_cmd, mode=a.mode, labels=a.labels, use_cache=not a.no_cache))
        if data.get("evaluation"):
            _print_eval(data["evaluation"])
        if a.open:
            webbrowser.open((Path(a.out) / "report.html").resolve().as_uri())
    elif a.cmd == "serve":
        from .server import serve
        serve(a.port, a.open)
    elif a.cmd == "pr":
        from .pr import export_prs
        rows = export_prs(a.audit_dir, a.repo, push=a.push, sandbox=a.sandbox,
                          only=a.only.split(",") if a.only else None)
        print(f"{sum(1 for r in rows if 'commit' in r)} branch(es) created")
    elif a.cmd == "evaluate":
        from .evaluate import evaluate
        _print_eval(evaluate(a.results, a.labels))
    elif a.cmd == "benchmark":
        from .agents.llm import LLM
        from .evaluate import compare_triage
        llms = [LLM("offline")] + [LLM(p, a.model, base_url=a.base_url) for p in a.provider]
        table = compare_triage(a.repo, a.labels, llms, a.mode, log=lambda m: None)
        print(f"\n{'triage agent':42}{'precision':>10}{'recall':>8}{'F1':>7}{'FP':>5}{'FN':>5}")
        for row in table:
            print(f"{row['agent'][:41]:42}{row['precision']:>10}{row['recall']:>8}{row['f1']:>7}{row['fp']:>5}{row['fn']:>5}")
            for m in row.get("mistakes", []):
                print(f"{'':4}mistake: {m}")
    elif a.cmd == "context":
        from .graph import CodeGraph
        from .rules import run_rules
        from .rank import rank
        from .context import build_context
        cg = CodeGraph.build(a.repo)
        fs, lv = run_rules(cg, mode=a.mode)
        fs = rank(cg, fs)
        f = next((x for x in fs if x.id == a.target or x.symbol_id == a.target or x.key == a.target), None)
        if f is None:
            sys.exit(f"no finding {a.target!r}. Findings: " + ", ".join(f"{x.id}={x.rule}" for x in fs[:20]))
        b = build_context(cg, f, lv.entry_symbols, budget_chars=a.budget)
        print(b.to_prompt())
        total = sum(len(l) for p in cg.modules.values() for l in cg.lines(p))
        print(f"\n[~{b.approx_tokens} tokens sent to the LLM, instead of ~{total // 4} tokens for the whole repo]")
    elif a.cmd == "providers":
        from .agents.llm import available_providers, detect_provider
        for p in available_providers():
            print(f"{'✓' if p['available'] else '·'} {p['name']:11} {p['note']:40} fast={p['fast']} smart={p['smart']}")
        print(f"\nauto -> {detect_provider()}")
    elif a.cmd == "graph":
        from .graph import CodeGraph
        cg = CodeGraph.build(a.repo)
        cg.save(a.out)
        print(json.dumps(cg.stats(), indent=2), f"\nsaved -> {a.out}")
    elif a.cmd == "top":
        from .graph import CodeGraph
        cg = CodeGraph.build(a.repo)
        def val(n):
            return cg.blast_radius(n) if a.by == "blast" else cg.metrics(n).get(a.by, 0)
        rows = sorted(((val(n), n) for n in cg.g.nodes
                       if cg.symbols[n].kind.value in ("function", "method", "class") and not cg.symbols[n].is_test),
                      reverse=True)[: a.n]
        for v, n in rows:
            print(f"{v:>8}  {n}")


if __name__ == "__main__":
    main()
