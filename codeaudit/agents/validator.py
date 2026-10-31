"""Validator agent — deterministic, no LLM. Nothing is trusted until it passes:

  1. syntax       every changed file still parses
  2. signature    the target keeps its name and parameters (callers don't break)
  3. compiles     py_compile on a temporary copy of the repo
  4. re-scan      the WHOLE pipeline (graph + rules) runs again on the patched copy:
                  the finding must disappear and no new medium/high finding may appear
  5. tests        optional: the project's own test suite on the patched copy
The original repository is never touched. Output includes a git-style unified diff.
"""
from __future__ import annotations
import ast
import difflib
import os
import py_compile
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import CodeGraph
from ..models import Finding, SymbolKind

COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "env", "__pycache__", "node_modules",
                                     "audit_out*", ".codeaudit_*", ".tox", ".mypy_cache", ".pytest_cache",
                                     "*.egg-info", "build", "dist")
DELETE = None          # value in Change.files meaning "delete this symbol" is handled by replace_symbol


@dataclass
class Change:
    files: dict[str, str]                 # relative path -> new full file text
    description: str
    by: str                               # "llm-agent" | "deterministic"
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------- editing helpers
def file_text(cg: CodeGraph, rel: str) -> str:
    with open(Path(cg.repo_root) / rel, encoding="utf-8", newline="") as fh:     # keep CRLF files intact
        return fh.read()


def _string_continuation_lines(code: str) -> set[int]:
    """1-based line numbers that are inside (not the first line of) a multi-line string literal."""
    import io
    import tokenize
    inside = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type == tokenize.STRING and tok.end[0] > tok.start[0]:
                inside |= set(range(tok.start[0] + 1, tok.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return inside


def _reindent(code: str, indent: str, protect_strings: bool = False) -> list[str]:
    code = textwrap.dedent(code).strip("\n")
    keep = _string_continuation_lines(code) if protect_strings else set()
    return [(l if i in keep else (indent + l if l.strip() else "")) + "\n"
            for i, l in enumerate(code.splitlines(), 1)]


def replace_symbol(cg: CodeGraph, sid: str, new_code: str | None, text: str | None = None,
                   protect_strings: bool = False) -> str:
    """Return the file text with symbol `sid` replaced by new_code (None = delete it)."""
    s = cg.symbols[sid]
    text = text if text is not None else file_text(cg, s.file)
    lines = text.splitlines(keepends=True)
    first = lines[s.def_line - 1]
    indent = first[: len(first) - len(first.lstrip())]
    if new_code is None or new_code.strip() in ("", "# DELETE", "#DELETE"):
        start, end = s.start_line - 1, s.end_line
        while end < len(lines) and not lines[end].strip() and (
                start == 0 or not lines[start - 1].strip()):
            end += 1                                        # swallow blank lines after
        if end >= len(lines) and start > 0:
            while start > 0 and not lines[start - 1].strip():
                start -= 1                                  # deleting at EOF: trim trailing blanks
        new = lines[:start] + lines[end:]
    else:
        stripped = textwrap.dedent(new_code).lstrip("\n")
        start = (s.start_line if stripped.startswith("@") else s.def_line) - 1
        new = lines[:start] + _reindent(new_code, indent, protect_strings) + lines[s.end_line:]
    out = "".join(new)
    return out if out.endswith("\n") else out + "\n"


def make_diff(cg: CodeGraph, files: dict[str, str]) -> str:
    parts = []
    for rel, new in files.items():
        old = file_text(cg, rel)
        parts.append("".join(difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}")))
    return "".join(parts)


def _find(tree: ast.AST, qualname: str):
    node = tree
    for p in qualname.split("."):
        node = next((c for c in ast.iter_child_nodes(node)
                     if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and c.name == p), None)
        if node is None:
            return None
    return node


def _params(fn) -> tuple:
    if isinstance(fn, ast.ClassDef):
        return ("class",)
    a = fn.args
    return (tuple(x.arg for x in a.posonlyargs + a.args), tuple(x.arg for x in a.kwonlyargs),
            a.vararg.arg if a.vararg else None, a.kwarg.arg if a.kwarg else None,
            len(a.defaults), len([d for d in a.kw_defaults if d is not None]))


# ---------------------------------------------------------------------- tests
def default_test_cmd(repo: str) -> list[str] | None:
    r = Path(repo)
    has_tests = any(r.glob("test*/**/test_*.py")) or any(r.glob("test_*.py")) or any(r.glob("**/tests/test_*.py"))
    return [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"] if has_tests else None


def run_tests(workdir: str, test_cmd, timeout: int = 300) -> tuple[bool, str]:
    cmd = shlex.split(test_cmd) if isinstance(test_cmd, str) else list(test_cmd)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    extra = [workdir] + ([str(Path(workdir) / "src")] if (Path(workdir) / "src").is_dir() else [])
    env["PYTHONPATH"] = os.pathsep.join(extra + [env.get("PYTHONPATH", "")])
    try:
        r = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return False, f"cannot run tests: {e}"
    tail = [l for l in (r.stdout + r.stderr).strip().splitlines() if l.strip()][-3:]
    return r.returncode == 0, " | ".join(tail)


def copy_repo(cg: CodeGraph, dest: str) -> Path:
    work = Path(dest) / "repo"
    shutil.copytree(cg.repo_root, work, ignore=COPY_IGNORE)
    return work


# ---------------------------------------------------------------------- validate
def validate(cg: CodeGraph, finding: Finding, change: Change, baseline_keys: set[str],
             mode: str = "auto", test_cmd=None, timeout: int = 300) -> dict:
    from ..rules import run_rules                     # local import: rules -> graph only
    checks: list[dict] = []
    sym = cg.symbols[finding.symbol_id]

    def check(name, ok, detail=""):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        return ok

    # 1. syntax
    trees = {}
    for rel, txt in change.files.items():
        try:
            trees[rel] = ast.parse(txt)
        except SyntaxError as e:
            check("syntax", False, f"{rel}: {e.msg} (line {e.lineno})")
            return _result(cg, checks, change)
    check("syntax", True, f"{len(trees)} file(s) parse")

    # 2. signature
    deleting = finding.rule == "DEAD_CODE" or (finding.rule == "CYCLIC_DEPENDENCY")
    if sym.kind in (SymbolKind.FUNCTION, SymbolKind.METHOD, SymbolKind.CLASS) and sym.file in trees:
        old_node = _find(ast.parse(file_text(cg, sym.file)), sym.qualname)
        new_node = _find(trees[sym.file], sym.qualname)
        if deleting:
            if not check("removed", new_node is None, f"{sym.qualname} removed" if new_node is None
                         else f"{sym.qualname} is still there"):
                return _result(cg, checks, change)
        else:
            ok = new_node is not None and _params(new_node) == _params(old_node)
            if not check("signature", ok, "same name and parameters" if ok else
                         ("target missing" if new_node is None else "parameters changed — callers would break")):
                return _result(cg, checks, change)

    with tempfile.TemporaryDirectory(prefix="codeaudit_") as tmp:
        work = copy_repo(cg, tmp)
        for rel, txt in change.files.items():
            (work / rel).write_text(txt, encoding="utf-8", newline="")
        # 3. compiles
        try:
            for rel in change.files:
                py_compile.compile(str(work / rel), doraise=True,
                                   cfile=str(Path(tmp) / "pyc" / (rel.replace("/", "_") + "c")))
            check("compiles", True)
        except py_compile.PyCompileError as e:
            check("compiles", False, str(e)[:300])
            return _result(cg, checks, change)
        # 4. re-scan the whole repository
        try:
            cg2 = CodeGraph.build(str(work))
            after, _ = run_rules(cg2, mode=mode)
        except Exception as e:                           # analysis itself must not crash
            check("re-scan", False, f"analysis failed: {type(e).__name__}: {e}")
            return _result(cg, checks, change)
        after_keys = {f.key for f in after}
        same_before = [k for k in baseline_keys if k.startswith(f"{finding.rule}:{finding.symbol_id}")]
        same_after = [f for f in after if f.rule == finding.rule and f.symbol_id == finding.symbol_id]
        resolved = finding.key not in after_keys or len(same_after) < len(same_before)
        check("finding resolved", resolved,
              "no longer reported" if resolved else "the static rule still reports it")
        new = [f for f in after if f.key not in baseline_keys and f.severity >= 0.5 and f.confidence >= 0.5]
        check("no new issues", not new,
              "" if not new else "; ".join(f"{f.rule}: {f.message}" for f in new[:3]))
        # 5. tests
        if test_cmd:
            ok, tail = run_tests(str(work), test_cmd, timeout)
            check("tests pass", ok, tail)
    return _result(cg, checks, change)


def _result(cg, checks, change) -> dict:
    failed = [c for c in checks if not c["passed"]]
    return {"ok": not failed, "checks": checks, "diff": make_diff(cg, change.files) if change.files else "",
            "feedback": "; ".join(f"{c['name']}: {c['detail']}" for c in failed),
            "by": change.by, "description": change.description}
