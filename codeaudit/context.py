"""Context assembly: the answer to "the LLM lacks repository context".

For one finding we pull from the graph ONLY what matters, within a character budget:
  - the target code
  - graph facts: entry path, taint path, blast radius, who uses it, cycle edges
  - callers / callees / related code (smallest first, degraded to signatures when over budget)
"""
from __future__ import annotations
import re
from .graph import CodeGraph
from .models import ContextBundle, Finding, SymbolKind


def signature_only(src: str) -> str:
    m = re.search(r"^\s*(async\s+def|def|class)\b.*?:\s*$", src, re.S | re.M)
    head = src[: m.end()].strip() if m else src.splitlines()[0]
    return head + " ..."


def _short(cg: CodeGraph, sid: str) -> str:
    s = cg.symbols[sid]
    return s.qualname or f"<module {s.module}>"


def _module_outline(cg: CodeGraph, mod: str, max_items: int = 40) -> str:
    lines = cg.lines(cg.modules[mod])
    imports = [l for l in lines if l.startswith(("import ", "from "))][:20]
    defs = [signature_only(cg.source(m)) for m in cg.members(f"{mod}:")][:max_items]
    return "\n".join(imports + [""] + defs)


def entry_path(cg: CodeGraph, sid: str, entry_symbols: set[str]) -> list[str] | None:
    """Shortest call path from a real entry point (tests only as a fallback)."""
    if not entry_symbols:
        return None
    real = {e for e in entry_symbols if not cg.symbols[e].is_test}
    return (cg.shortest_path(real, sid) if real else None) or cg.shortest_path(entry_symbols, sid)


def build_context(cg: CodeGraph, f: Finding, entry_symbols: set[str] | None = None,
                  budget_chars: int = 12000, max_neighbors: int = 5) -> ContextBundle:
    sid = f.symbol_id
    s = cg.symbols[sid]
    ev = f.evidence
    if s.kind == SymbolKind.MODULE:
        target_src = _module_outline(cg, s.module)
    else:
        target_src = cg.source(sid)
    b = ContextBundle(target_id=sid, target_source=target_src, metrics=cg.metrics(sid),
                      finding_summary=f"{f.rule} ({f.category}{', ' + f.cwe if f.cwe else ''}) — {f.message}\n"
                                      f"Static-rule confidence: {f.confidence}")
    facts = b.facts
    if s.kind != SymbolKind.MODULE and entry_symbols is not None:
        p = entry_path(cg, sid, entry_symbols)
        facts.append("Reachable from an entry point: " + " -> ".join(_short(cg, x) for x in p) if p
                     else "NOT reachable from any entry point (no call/reference path)")
    if ev.get("taint"):
        facts.append(f"Taint analysis: {ev['taint']}")
    if ev.get("taint_path") and len(ev["taint_path"]) > 1:
        facts.append("Taint path: " + " -> ".join(_short(cg, x) for x in ev["taint_path"]))
    if f.rule == "HARDCODED_SECRET":
        facts.append(f"Assigned value starts with {ev.get('value_preview')!r}"
                     + (" (looks like a URL/path)" if ev.get("looks_like_url") else ""))
    users = cg.users(sid)
    facts.append(f"Used by {len(users)} symbol(s); blast radius {cg.blast_radius(sid)} "
                 f"(functions that depend on it transitively); module centrality {cg.centrality(sid)}")
    if f.rule == "DEAD_CODE":
        if ev.get("users"):
            facts.append("Its only users are themselves dead: " + ", ".join(_short(cg, u) for u in ev["users"]))
        if ev.get("possibly_dynamic"):
            facts.append(f"Possibly used dynamically: {ev['possibly_dynamic']}")
        facts.append(f"Analysis mode: {ev.get('mode')} (library mode treats public names as API)")
    if f.rule == "CYCLIC_DEPENDENCY":
        for e in ev["edges"]:
            who = ", ".join(_short(cg, u) for u in e["users"]) or "nothing (unused import)"
            tag = " [all users are dead code]" if e["dead_users_only"] else ""
            facts.append(f"Import edge {e['src']} -> {e['dst']} (line {e['lines']}) used by: {who}{tag}")
        facts.append(f"Hint: {ev['hint']}")
    if ev.get("in_dead_code"):
        facts.append("This code is itself unreachable (dead code)")

    used = len(b.to_prompt())

    def add(ids, dest):
        nonlocal used
        for nid in sorted(ids, key=lambda x: cg.symbols[x].length)[:max_neighbors]:
            if cg.symbols[nid].kind == SymbolKind.MODULE:
                continue
            src = cg.source(nid, max_lines=80)
            if used + len(src) > budget_chars:
                src = signature_only(src)
                if used + len(src) > budget_chars:
                    continue
            dest.append({"id": nid, "file": cg.symbols[nid].file, "source": src})
            used += len(src) + 40

    if f.rule == "CYCLIC_DEPENDENCY":
        add([u for e in ev["edges"] for u in e["users"]], b.related)
    elif s.kind != SymbolKind.MODULE:
        imps = cg.imports.get(s.module, {})
        b.imports = [f"{a} -> {t}" for a, t in list(imps.items())[:20]]
        p = cg.parent(sid)
        if p and cg.symbols[p].kind == SymbolKind.CLASS:
            b.siblings = [signature_only(cg.source(m)) for m in cg.members(p) if m != sid][:15]
        used = len(b.to_prompt())
        add(cg.callees(sid), b.callees)
        add(users, b.callers)
    b.approx_tokens = len(b.to_prompt()) // 4
    return b
