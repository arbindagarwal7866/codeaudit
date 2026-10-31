"""Agent 3 — Refactorer: an agent loop with tools, checked by the Validator after every attempt.

LLM mode (any provider):
  the model can call tools  get_source / get_callers / get_callees / search
  then submits new code -> Validator (compile + full re-scan + tests) -> on rejection the
  validator's feedback goes back to the model, which tries again (max 3 submissions).
Offline mode, or when the LLM can't produce a valid patch: deterministic AST fixers.
"""
from __future__ import annotations
import json
from pathlib import Path

from ..graph import CodeGraph
from ..models import Finding, ContextBundle, SymbolKind
from .llm import LLM, LLMError, extract_code, parse_json
from .validator import Change, replace_symbol
from .fixers import deterministic_fix

LLM_RULES = {"SQL_INJECTION", "CODE_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION",
             "WEAK_HASH", "TLS_VERIFY_DISABLED", "HARDCODED_SECRET", "INSECURE_TEMPFILE",
             "DEAD_CODE", "DEEP_NESTING", "COMPLEX_METHOD", "LONG_METHOD"}

SYSTEM = """You are an autonomous refactoring agent working inside a Python repository.
Your job: fix ONE reported issue in ONE target symbol while keeping behaviour identical.

You may use tools. To call one, reply with ONLY a JSON object, for example:
  {"tool": "get_source",  "symbol": "pkg.mod:Class.method"}
  {"tool": "get_callers", "symbol": "pkg.mod:func"}      (who calls it, with their code)
  {"tool": "get_callees", "symbol": "pkg.mod:func"}
  {"tool": "search", "text": "execute("}                (matching lines across the repo, max 20)

When you are ready, submit by replying with ONE ```python code block containing the complete new
version of the target symbol (nothing else outside the block). Rules for the submission:
- keep the same name, parameters and defaults; decorators may be omitted (they are kept automatically)
- you may add small private helper functions right after the target, at the same indentation
- no new third-party imports; if you need a standard-library import, do it inside the function
- to delete dead code, submit a block containing only:  # DELETE
A validator then compiles your code, re-runs the whole static analysis on the repository and runs
the tests. If it rejects the code you will get the reason and can try again."""


def _tool(cg: CodeGraph, action: dict) -> str:
    name, sym = action.get("tool"), action.get("symbol", "")
    if name in ("get_source", "get_callers", "get_callees"):
        if sym not in cg.symbols:
            close = [s for s in cg.symbols if s.endswith(sym.split(":")[-1])][:5]
            return f"unknown symbol {sym!r}. Did you mean: {close}"
        if name == "get_source":
            return cg.source(sym, max_lines=150)
        ids = cg.users(sym) if name == "get_callers" else cg.uses(sym)
        if not ids:
            return "none"
        return "\n\n".join(f"# {i} ({cg.symbols[i].file})\n{cg.source(i, max_lines=40)}" for i in ids[:6])
    if name == "search":
        text = str(action.get("text", ""))[:100]
        if not text:
            return "empty search"
        out = []
        for mod, path in cg.modules.items():
            for no, line in enumerate(cg.lines(path), 1):
                if text in line:
                    out.append(f"{path}:{no}: {line.strip()}")
                    if len(out) >= 20:
                        return "\n".join(out)
        return "\n".join(out) or "no matches"
    return f"unknown tool {name!r}; use get_source, get_callers, get_callees, search, or submit code"


def agentic_refactor(llm: LLM, cg: CodeGraph, f: Finding, ctx: ContextBundle, analysis: dict,
                     validate_fn, max_steps: int = 8, max_submits: int = 3) -> dict:
    plan = "\n".join(f"- {x}" for x in analysis.get("fix_plan", []))
    first = (f"Issue to fix: {f.rule} — {f.message}\nFix plan from the analyst:\n{plan}\n\n"
             f"{ctx.to_prompt()}\n\nTarget symbol id: {f.symbol_id}")
    messages = [{"role": "user", "content": first}]
    transcript, submits, last = [], 0, None
    for step in range(1, max_steps + 1):
        rep = llm.chat(SYSTEM, messages, smart=True, max_tokens=8000)
        messages.append({"role": "assistant", "content": rep.raw if llm.style == "anthropic" else rep.text})
        code = extract_code(rep.text)
        if code is not None:
            submits += 1
            delete = code.strip() in ("# DELETE", "#DELETE")
            sym = cg.symbols[f.symbol_id]
            change = Change({sym.file: replace_symbol(cg, f.symbol_id, None if delete else code)},
                            "LLM rewrite of " + (sym.qualname or sym.module), "llm-agent")
            last = validate_fn(change)
            transcript.append({"step": step, "action": "submit patch",
                               "result": "PASS" if last["ok"] else "REJECTED: " + last["feedback"]})
            if last["ok"]:
                return {"ok": True, "attempts": submits, "validation": last, "transcript": transcript}
            if submits >= max_submits:
                break
            messages.append({"role": "user", "content":
                             f"The validator rejected your code:\n{last['feedback']}\nFix it and submit again."})
            continue
        try:
            action = parse_json(rep.text)
        except ValueError:
            action = None
        if not action or "tool" not in action:
            transcript.append({"step": step, "action": "(no tool call / code)", "result": rep.text[:100]})
            messages.append({"role": "user", "content":
                             "Reply with either a JSON tool call or one ```python block with the new code."})
            continue
        result = _tool(cg, action)
        arg = action.get("symbol") or action.get("text") or ""
        transcript.append({"step": step, "action": f"{action['tool']}({arg})",
                           "result": result.splitlines()[0][:100] if result else ""})
        messages.append({"role": "user", "content": f"Result of {action['tool']}:\n{result[:6000]}"})
    return {"ok": False, "attempts": submits, "validation": last, "transcript": transcript}


def refactor(llm: LLM, cg: CodeGraph, f: Finding, ctx: ContextBundle, analysis: dict, validate_fn) -> dict:
    """Try the LLM agent first (if available), then the deterministic fixer. Returns the best attempt."""
    tried = []
    sym = cg.symbols[f.symbol_id]
    if not llm.offline and f.rule in LLM_RULES and sym.kind != SymbolKind.MODULE:
        try:
            r = agentic_refactor(llm, cg, f, ctx, analysis, validate_fn)
            r["by"] = "llm-agent"
            if r["ok"]:
                return r
            tried.append(r)
        except (LLMError, ValueError) as e:
            tried.append({"ok": False, "by": "llm-agent", "error": str(e)[:200], "transcript": []})
    ch = deterministic_fix(cg, f)
    if ch is not None:
        v = validate_fn(ch)
        r = {"ok": v["ok"], "attempts": 1, "validation": v, "by": "deterministic", "notes": ch.notes,
             "transcript": [{"step": 1, "action": "deterministic AST fixer",
                             "result": "PASS" if v["ok"] else "REJECTED: " + v["feedback"]}]}
        if tried:
            r["llm_attempt"] = tried[-1]
        return r
    if tried:
        return tried[-1]
    return {"ok": False, "attempts": 0, "by": "none", "validation": None, "transcript": [],
            "error": "no automatic fix for this kind of issue — follow the fix plan"}
