"""Agent 1 — Triage: is this static finding a REAL problem or a false alarm?

LLM mode: the model judges using the graph-built context (callers, taint path, entry path ...).
Offline mode / LLM failure: transparent heuristic rules over the same graph evidence.
"""
from __future__ import annotations
import ast
import re
import textwrap

from ..graph import CodeGraph
from ..models import Finding, ContextBundle
from .llm import LLM

SYSTEM = """You are a senior Python security and architecture reviewer triaging static-analysis findings.
Static rules are noisy: they match patterns without understanding intent. You also receive facts computed
from the repository's dependency graph (entry path, taint path, who uses the code, cycle edges).
Decide if the finding is a REAL problem worth a developer's time.

Typical false positives:
- weak hash (MD5/SHA-1) used only as a cache key, ETag or checksum, or required by a protocol
- a sink (eval, SQL, shell) whose argument is a constant, or where every caller passes constants
- a "secret" that is really a URL, a placeholder or an environment-variable name
- "dead code" that is looked up dynamically (getattr with a computed name, registries, plugins)
- long parameter lists that mirror a public, backward-compatible API
- long functions that are mostly data tables or docstrings; complexity from flat guard clauses

JSON keys:
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE"
  "confidence": number 0..1
  "reason": one or two plain sentences that cite the specific evidence"""

_NON_SECURITY_HASH = re.compile(r"cache|key|etag|checksum|fingerprint|digest|bucket|shard|dedup|id\b", re.I)
_PASSWORD = re.compile(r"passw|pwd|passwd", re.I)
_PLACEHOLDER = re.compile(r"changeme|change_me|xxx|your[_-]|example|dummy|placeholder|<.*>|test", re.I)
_SHARED_MODULES = {"exceptions", "types", "_types", "constants", "compat", "settings", "config", "typing", "errors"}


def _fn_node(cg: CodeGraph, sid: str):
    try:
        tree = ast.parse(textwrap.dedent(cg.source(sid, max_lines=10_000)))
    except SyntaxError:
        return None
    return next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)


def heuristic_triage(cg: CodeGraph, f: Finding, mode: str = "app") -> dict:
    ev, s = f.evidence, cg.symbols[f.symbol_id]

    def v(tp, conf, reason):
        return {"verdict": "TRUE_POSITIVE" if tp else "FALSE_POSITIVE", "confidence": conf, "reason": reason}

    if f.rule in ("SQL_INJECTION", "CODE_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION",
                  "TEMPLATE_INJECTION"):
        if ev.get("constant_args"):
            return v(False, 0.85, "The sink only receives a constant, so no outside data can reach it.")
        if "pass constants" in str(ev.get("taint", "")):
            return v(False, 0.75, f"Every caller passes constants for the parameters used ({ev['taint']}).")
        if ev.get("taint_path"):
            return v(True, 0.9, f"User input reaches the sink: {ev['taint']}.")
        return v(True, 0.65, "Non-constant data reaches a dangerous sink; source not proven but plausible.")
    if f.rule == "WEAK_HASH":
        lines = cg.lines(s.file)
        line = lines[f.start_line - 1]
        call_text = line.split("hexdigest")[0].split("digest()")[0]
        if _PASSWORD.search(call_text):
            return v(True, 0.85, "A password goes through MD5/SHA-1: fast hashes are cracked by brute force; "
                                 "use bcrypt/argon2/scrypt/PBKDF2.")
        module_text = "\n".join(lines).lower()
        if "hmac" in module_text or re.search(r"sign(er|ature)", s.file + " " + s.qualname, re.I):
            return v(False, 0.6, "SHA-1 inside HMAC/signing is not broken, and changing the default "
                                 "would invalidate every existing signature.")
        prev = lines[f.start_line - 2].strip() if f.start_line > 1 else ""
        comments = (prev if prev.startswith("#") else "") + (line.split("#", 1)[1] if "#" in line else "")
        if _NON_SECURITY_HASH.search(s.qualname + " " + call_text + " " + comments):
            return v(False, 0.7, "The hash is used as a cache key / checksum, not for passwords or signatures.")
        return v(True, 0.6, "MD5/SHA-1 output may be used for security; prefer SHA-256 or a password KDF.")
    if f.rule == "HARDCODED_SECRET":
        if ev.get("looks_like_url"):
            return v(False, 0.85, "The value is a URL/path, not a credential; only the variable name matched.")
        if _PLACEHOLDER.search(str(ev.get("value_preview", ""))):
            return v(False, 0.6, "The value looks like a placeholder, not a real credential.")
        return v(True, 0.8, "A credential-like literal is committed to source control.")
    if f.rule in ("TLS_VERIFY_DISABLED", "INSECURE_TEMPFILE"):
        return v(True, 0.75, "Insecure API use with a known safer alternative.")
    if f.rule == "DEAD_CODE":
        if ev.get("possibly_dynamic"):
            return v(False, 0.7, f"It may be called dynamically: {ev['possibly_dynamic']}.")
        if ev.get("transitive"):
            return v(True, 0.85, "Its only callers are themselves unreachable, so the whole chain is dead.")
        return v(True, 0.8, "Nothing reaches it from any entry point (main, tests, framework hooks, exports).")
    if f.rule == "UNUSED_MODULE":
        return v(True, 0.7, "No module imports it and it is not runnable on its own.")
    if f.rule == "CYCLIC_DEPENDENCY":
        return v(True, 0.85, "Modules import each other; the cycle makes import order fragile and blocks reuse.")
    if f.rule == "HUB_MODULE":
        if s.module.split(".")[-1] in _SHARED_MODULES:
            return v(False, 0.6, "Shared definitions module (types/exceptions/config) is expected to be imported widely.")
        return v(True, 0.6, "High fan-in AND fan-out: changes here ripple to dependents and dependencies.")
    if f.rule == "GOD_MODULE":
        return v(True, 0.6, "Too much code and logic in one file; split by responsibility.")
    if f.rule == "GOD_CLASS":
        if ev.get("coupling_out", 0) <= 3 and ev.get("sum_complexity", 0) <= 1.6 * ev.get("num_methods", 1):
            return v(False, 0.55, "Many small, simple methods with low coupling: a data/collection class, not a god class.")
        return v(True, 0.7, "Many methods, high total complexity and coupling to many other units.")
    if f.rule == "LONG_PARAM_LIST":
        fn = _fn_node(cg, f.symbol_id)
        if mode == "library" and not s.name.startswith("_"):
            return v(False, 0.6, "Public API signature: changing it would break library users.")
        if fn is not None:
            a = fn.args
            n_def = len(a.defaults) + len([d for d in a.kw_defaults if d is not None])
            if n_def >= 0.6 * max(1, s.num_params):
                return v(False, 0.55, "Most parameters are optional keyword settings with defaults.")
        return v(True, 0.65, "Many required parameters: easy to call in the wrong order; group them.")
    if f.rule == "LONG_METHOD":
        fn = _fn_node(cg, f.symbol_id)
        if fn is not None:
            data_lines = set()
            for n in ast.walk(fn):
                if isinstance(n, (ast.Dict, ast.List, ast.Set, ast.Tuple)) and n.end_lineno - n.lineno >= 3:
                    data_lines |= set(range(n.lineno, n.end_lineno + 1))
            doc = ast.get_docstring(fn) or ""
            ratio = (len(data_lines) + doc.count("\n")) / max(1, s.length)
            if ratio >= 0.4:
                return v(False, 0.6, f"About {ratio:.0%} of it is data literals/docstring, not logic.")
        return v(True, 0.65, "Long function mixing several steps; harder to read and test.")
    if f.rule == "COMPLEX_METHOD":
        if s.max_nesting <= 1:
            return v(False, 0.55, "Complexity comes from flat, readable guard clauses (nesting depth <= 1).")
        return v(True, 0.7, "Many nested decision paths; each needs its own test.")
    if f.rule == "DEEP_NESTING":
        return v(True, 0.75, "Deeply nested blocks are hard to follow; guard clauses can flatten them.")
    return v(True, 0.5, "No specific heuristic; kept for review.")


def triage(llm: LLM, cg: CodeGraph, f: Finding, ctx: ContextBundle, mode: str = "app") -> dict:
    h = heuristic_triage(cg, f, mode)
    if llm.offline:
        out = {**h, "mode": "heuristic"}
    else:
        try:
            r = llm.ask_json(SYSTEM, ctx.to_prompt(), max_tokens=3000)
            verdict = str(r.get("verdict", "")).upper().replace(" ", "_")
            if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
                raise ValueError(f"bad verdict {verdict!r}")
            out = {"verdict": verdict, "confidence": float(r.get("confidence", 0.6)),
                   "reason": str(r.get("reason", "")), "mode": "llm", "heuristic_verdict": h["verdict"]}
        except Exception as e:
            out = {**h, "mode": f"heuristic (LLM failed: {str(e)[:120]})"}
    f.llm_verdict = out["verdict"]
    return out
