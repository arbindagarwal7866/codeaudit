"""Agent 2 — Analyst: explain a confirmed finding (root cause, impact across the repo, fix plan)."""
from __future__ import annotations
from ..graph import CodeGraph
from ..models import Finding, ContextBundle
from .llm import LLM

SYSTEM = """You are a software architect explaining a confirmed issue to the developer who owns the code.
Use the repository facts (entry path, taint path, callers, blast radius, cycle edges) to judge impact
ACROSS the repository, not just inside one function. Be concrete and short.

JSON keys:
  "summary": one plain-English sentence
  "root_cause": why the code ended up like this
  "impact": what can go wrong, naming affected callers / entry points when relevant
  "cwe": CWE id string if security-related, else null
  "fix_plan": list of 2-5 short concrete refactoring steps
  "effort": "small" | "medium" | "large"
  "refactorable": true if an automatic patch to this one symbol/file is safe"""

AUTO_RULES = {"SQL_INJECTION", "CODE_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION",
              "WEAK_HASH", "TLS_VERIFY_DISABLED", "HARDCODED_SECRET", "DEAD_CODE", "CYCLIC_DEPENDENCY",
              "DEEP_NESTING", "COMPLEX_METHOD", "LONG_METHOD", "LONG_PARAM_LIST"}

_TEMPLATES = {
    "SQL_INJECTION": ("User-controlled text is pasted into an SQL string.",
                      "The query is built with f-strings / concatenation instead of driver parameters.",
                      ["Replace the formatted string with placeholders (? or %s)",
                       "Pass the values as the second argument of execute()",
                       "Add a test with a quote character in the input"]),
    "CODE_INJECTION": ("eval()/exec() runs whatever text reaches it as Python code.",
                       "Dynamic evaluation was used to parse simple values or expressions.",
                       ["Use ast.literal_eval for literals", "Or parse the expression with a whitelist",
                        "Never pass user input to eval/exec"]),
    "COMMAND_INJECTION": ("A shell command is built from a string, so arguments can inject shell syntax.",
                          "shell=True / os.system was used for convenience.",
                          ["Pass the command as a list of arguments", "Drop shell=True",
                           "Validate file names before using them"]),
    "INSECURE_DESERIALIZATION": ("Untrusted bytes are deserialized with a format that can execute code.",
                                 "pickle/yaml.load were used to restore objects.",
                                 ["Switch to json or yaml.safe_load", "Sign data if pickle is unavoidable"]),
    "TEMPLATE_INJECTION": ("Text that reaches the template source is executed as Jinja code (SSTI), "
                           "which can read config/secrets or run code, and also allows XSS.",
                           "The template string is built with formatting/concatenation instead of passing values.",
                           ["Keep the template a constant (or a file via render_template)",
                            "Pass user values as template variables: render_template_string(T, name=name)",
                            "Let Jinja autoescape them; never mark user text |safe"]),
    "WEAK_HASH": ("MD5/SHA-1 are broken for security purposes.", "Legacy hashing choice.",
                  ["Use hashlib.sha256 (or a password KDF like bcrypt/argon2 for passwords)",
                   "Migrate stored hashes"]),
    "HARDCODED_SECRET": ("A credential is committed in source code.", "Configuration kept in code.",
                         ["Read it from an environment variable or a secrets manager",
                          "Rotate the leaked value", "Add the config file to .gitignore"]),
    "TLS_VERIFY_DISABLED": ("TLS certificates are not checked, allowing man-in-the-middle attacks.",
                            "verify=False added to silence certificate errors.",
                            ["Remove verify=False", "Point verify= to a CA bundle if a private CA is used"]),
    "INSECURE_TEMPFILE": ("mktemp() returns a name another process can grab first.", "Old API.",
                          ["Use tempfile.mkstemp() or NamedTemporaryFile()"]),
    "DEAD_CODE": ("This code can never run.", "Leftover from removed features or refactors.",
                  ["Delete it (version control keeps the history)", "Delete code that only it used"]),
    "UNUSED_MODULE": ("This file is never imported.", "Leftover module.",
                      ["Confirm it's not a script run by hand", "Delete it or move it to scripts/"]),
    "CYCLIC_DEPENDENCY": ("Modules import each other in a loop.",
                          "Responsibilities leaked across modules over time.",
                          ["Remove edges used only by dead code", "Move shared code into a new lower-level module",
                           "Or invert the dependency (pass a callback / interface)"]),
    "GOD_MODULE": ("One file holds too much unrelated code.", "Features were added where it was convenient.",
                   ["Group functions by responsibility", "Split into sub-modules", "Keep a thin facade for imports"]),
    "HUB_MODULE": ("A module many others depend on also depends on many others.",
                   "It became a crossroads for unrelated features.",
                   ["Split stable core definitions from volatile logic", "Depend on the core part only"]),
    "GOD_CLASS": ("One class has too many responsibilities.", "Methods accumulated in one place.",
                  ["Identify method groups that share fields", "Extract each group into its own class"]),
    "LONG_METHOD": ("The function is long and does several things.", "Steps were appended over time.",
                    ["Extract each step into a well-named helper", "Keep the original as a short coordinator"]),
    "COMPLEX_METHOD": ("Too many decision paths to test and reason about.", "Special cases piled up.",
                       ["Use guard clauses / early returns", "Extract branches into helpers",
                        "Replace if/elif chains with a lookup table"]),
    "LONG_PARAM_LIST": ("Callers must pass many arguments in the right order.", "Parameters added one by one.",
                        ["Group related parameters into a dataclass", "Make optional ones keyword-only"]),
    "DEEP_NESTING": ("Deeply nested blocks hide the main logic.", "Conditions were nested instead of inverted.",
                     ["Return/continue early on the negative case", "Merge nested ifs with and",
                      "Extract the innermost block"]),
}


def heuristic_analysis(cg: CodeGraph, f: Finding, ctx: ContextBundle) -> dict:
    summary, root, plan = _TEMPLATES.get(f.rule, ("Issue found.", "Unknown.", ["Review manually"]))
    callers = cg.users(f.symbol_id)
    impact = [f"{len(callers)} direct user(s), blast radius {cg.blast_radius(f.symbol_id)}."]
    for fact in ctx.facts:
        if fact.startswith(("Taint path", "Reachable from", "Import edge")):
            impact.append(fact + ".")
    if f.rule == "CYCLIC_DEPENDENCY":
        plan = [f.evidence["hint"]] + plan[1:]
    return {"summary": summary, "root_cause": root, "impact": " ".join(impact[:4]), "cwe": f.cwe,
            "fix_plan": plan, "effort": "small" if f.rule in ("DEAD_CODE", "WEAK_HASH", "TLS_VERIFY_DISABLED")
            else "medium", "refactorable": f.rule in AUTO_RULES}


def analyze(llm: LLM, cg: CodeGraph, f: Finding, ctx: ContextBundle) -> dict:
    if llm.offline:
        return {**heuristic_analysis(cg, f, ctx), "mode": "heuristic"}
    try:
        out = llm.ask_json(SYSTEM, ctx.to_prompt(), max_tokens=4000)
        out.setdefault("fix_plan", [])
        if isinstance(out["fix_plan"], str):
            out["fix_plan"] = [out["fix_plan"]]
        out["refactorable"] = bool(out.get("refactorable", f.rule in AUTO_RULES))
        out["mode"] = "llm"
        return out
    except Exception as e:
        return {**heuristic_analysis(cg, f, ctx), "mode": f"heuristic (LLM failed: {str(e)[:120]})"}
