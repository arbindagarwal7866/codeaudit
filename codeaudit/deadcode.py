"""Dead-code detection = reachability on the dependency graph.

Dead code is NOT "an unused variable" (that's linting). Here, a function/class is dead when it
cannot be reached from any entry point by following calls and references.

Entry points (roots):
  - module-level code of every live module   (runs at import time)
  - `if __name__ == "__main__":` modules, test files, conftest, setup/manage/wsgi/asgi
  - names in __all__ and names re-exported from a package __init__
  - functions registered by framework decorators (@app.route, @pytest.fixture, @click.command ...)
  - library mode only: every public (non _private) top-level name = public API

From a live class we keep: dunder methods, bases, and methods whose name is accessed as an
attribute anywhere (obj.<name>) — because `obj.method()` calls can't be resolved statically.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from .graph import CodeGraph, CODE_KINDS
from .models import SymbolKind
from .parse import is_framework_decorator

ENTRY_FILE_NAMES = {"__main__", "setup", "conftest", "manage", "wsgi", "asgi", "main", "app",
                    "cli", "run", "server", "noxfile", "fabfile", "tasks"}


@dataclass
class Liveness:
    mode: str
    entry_modules: list[str]
    live: set[str]
    dead: list[dict] = field(default_factory=list)          # {symbol_id, users, possibly_dynamic, reason}
    unused_modules: list[str] = field(default_factory=list)
    entry_symbols: set[str] = field(default_factory=set)    # used to build entry paths


def detect_mode(cg: CodeGraph) -> str:
    root = Path(cg.repo_root)
    return "library" if any((root / f).exists() for f in ("pyproject.toml", "setup.py", "setup.cfg")) else "app"


def _is_public(name: str) -> bool:
    return not name.startswith("_") or (name.startswith("__") and name.endswith("__"))


_PLAIN_BASES = {"object", "ABC", "Generic", "Protocol", "NamedTuple", "TypedDict", "Enum", "IntEnum",
                "StrEnum", "Flag", "IntFlag", "str", "int", "float", "dict", "list", "tuple", "set"}


def _has_framework_base(cg: CodeGraph, cid: str) -> bool:
    """A base class from outside the repo (BaseHTTPRequestHandler, unittest.TestCase, View ...) calls
    the subclass's methods itself (do_GET, setUp, get), so its public methods count as overrides."""
    external = 0
    for b in cg.symbols[cid].bases:
        leaf = b.split("[")[0].split(".")[-1]
        if leaf not in _PLAIN_BASES and not leaf.endswith(("Error", "Exception", "Warning")):
            external += 1
    return external > len(cg.bases(cid))


def _dynamic_hit(cg: CodeGraph, sid: str) -> str | None:
    s = cg.symbols[sid]
    if s.name in cg.strings:
        return f"the name '{s.name}' appears as a string literal (registry / getattr / config?)"
    msym = cg.symbols.get(f"{s.module}:")
    for p in (msym.dynamic_prefixes if msym else []):
        if p and s.name.startswith(p):
            return f"module looks names up dynamically with prefix '{p}' (getattr)"
        if p == "" and s.kind == SymbolKind.METHOD:
            return "module uses getattr() with a computed name"
    return None


def analyze_liveness(cg: CodeGraph, mode: str = "auto") -> Liveness:
    mode = detect_mode(cg) if mode == "auto" else mode
    syms = cg.symbols

    # ---------------------------------------------------------- live modules
    entries = set()
    for m, path in cg.modules.items():
        s = syms.get(f"{m}:")
        leaf = m.split(".")[-1]
        if (m in cg.test_modules or (s and s.has_main_guard) or leaf in ENTRY_FILE_NAMES
                or "." not in m and not path.endswith("__init__.py") and mode == "app"
                or mode == "library"):
            entries.add(m)
    live_mods, q = set(entries), deque(entries)
    while q:
        m = q.popleft()
        nxt = list(cg.mg.successors(m))
        parts = m.split(".")
        nxt += [".".join(parts[:i]) for i in range(1, len(parts))]   # importing a.b runs a/__init__
        for d in nxt:
            if d in cg.modules and d not in live_mods:
                live_mods.add(d); q.append(d)

    # ---------------------------------------------------------- roots
    roots: set[str] = set()
    for m in live_mods:
        roots.add(f"{m}:")
        msym = syms.get(f"{m}:")
        for name in (msym.exports if msym else []):
            sid = cg._by_mq.get((m, name)) or cg._resolve_name(m, name)
            if sid:
                roots.add(sid)
        if cg.modules[m].endswith("__init__.py"):
            for alias, tgt in cg.imports.get(m, {}).items():
                sid = cg._lookup_fq(tgt)
                if sid and syms[sid].kind != SymbolKind.MODULE:
                    roots.add(sid)
    for sid, s in syms.items():
        if s.module not in live_mods or s.kind == SymbolKind.MODULE:
            continue
        if s.is_test:
            roots.add(sid)
        elif any(is_framework_decorator(d) for d in s.decorators):
            roots.add(sid)
        elif mode == "library" and "." not in s.qualname and _is_public(s.name):
            roots.add(sid)

    # ---------------------------------------------------------- propagate
    live, q = set(roots), deque(roots)

    def mark(x):
        if x not in live:
            live.add(x); q.append(x)

    while q:
        n = q.popleft()
        s = syms[n]
        for u in cg.uses(n):
            mark(u)
        if s.kind == SymbolKind.CLASS:
            for b in cg.bases(n):
                mark(b)
            base_methods = {syms[m].name for b in cg.bases(n) for m in cg.members(b)}
            framework_base = _has_framework_base(cg, n)
            for mem in cg.members(n):
                ms = syms[mem]
                dunder = ms.name.startswith("__") and ms.name.endswith("__")
                if (dunder or ms.name in cg.attrs or ms.name in base_methods
                        or any(is_framework_decorator(d) for d in ms.decorators)
                        or (framework_base and _is_public(ms.name))
                        or (mode == "library" and _is_public(ms.name))):
                    mark(mem)
        if s.kind in CODE_KINDS or s.kind == SymbolKind.CLASS:
            p = cg.parent(n)
            if p and syms[p].kind == SymbolKind.CLASS:
                mark(p)
        if s.kind == SymbolKind.CLASS:              # subclass methods overriding a live method
            for sub in cg.subclasses(n):
                if sub in live:
                    for mem in cg.members(sub):
                        if syms[mem].name in {syms[x].name for x in cg.members(n) if x in live}:
                            mark(mem)

    # ---------------------------------------------------------- report
    res = Liveness(mode=mode, entry_modules=sorted(entries), live=live)
    res.entry_symbols = {f"{m}:" for m in entries} | {r for r in roots if syms[r].kind != SymbolKind.MODULE}
    for m in sorted(set(cg.modules) - live_mods):
        if m not in cg.test_modules and not cg.modules[m].endswith("__init__.py"):
            res.unused_modules.append(m)
    for sid, s in syms.items():
        if (sid in live or s.kind == SymbolKind.MODULE or s.is_test or s.module not in live_mods):
            continue
        p = cg.parent(sid)
        if p and syms[p].kind != SymbolKind.MODULE and p not in live:
            continue                                   # report only the outermost dead symbol
        users = [u for u in cg.users(sid) if syms[u].kind != SymbolKind.MODULE or u in live]
        res.dead.append({"symbol_id": sid, "users": users,
                         "possibly_dynamic": _dynamic_hit(cg, sid),
                         "transitive": bool(users)})
    return res
