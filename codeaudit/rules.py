"""
Stage 4: Static rules — cheap, deterministic candidate generation in 4 categories.

ARCHITECTURE (module relationships, from the module graph)
  CYCLIC_DEPENDENCY   modules import each other in a loop
  GOD_MODULE          one file holds too much code / logic
  HUB_MODULE          imported by many AND imports many (change ripples everywhere)
  GOD_CLASS           one class does too much
SECURITY (AST sinks mapped to CWE + taint path from user input)
  SQL_INJECTION, CODE_INJECTION, COMMAND_INJECTION, INSECURE_DESERIALIZATION, TEMPLATE_INJECTION,
  HARDCODED_SECRET, WEAK_HASH, TLS_VERIFY_DISABLED, INSECURE_TEMPFILE
DEAD CODE (reachability from entry points, see deadcode.py)
  DEAD_CODE, UNUSED_MODULE
SMELL (function level)
  LONG_METHOD, COMPLEX_METHOD, LONG_PARAM_LIST, DEEP_NESTING
"""
from __future__ import annotations
from dataclasses import dataclass
import networkx as nx

from .graph import CodeGraph, CODE_KINDS
from .deadcode import analyze_liveness, Liveness
from .models import Finding, SymbolKind, Category


@dataclass
class Thresholds:
    long_method_loc: int = 60
    complex_cc: int = 10
    long_params: int = 5
    deep_nesting: int = 4
    god_methods: int = 20
    god_sum_cc: int = 60
    god_coupling: int = 8
    god_module_loc: int = 600
    god_module_defs: int = 25
    god_module_cc: int = 150
    hub_in: int = 5
    hub_out: int = 5


SECURITY_SEVERITY = {
    "SQL_INJECTION": 0.95, "CODE_INJECTION": 0.95, "COMMAND_INJECTION": 0.9,
    "INSECURE_DESERIALIZATION": 0.85, "TEMPLATE_INJECTION": 0.85, "HARDCODED_SECRET": 0.75, "TLS_VERIFY_DISABLED": 0.7,
    "WEAK_HASH": 0.5, "INSECURE_TEMPFILE": 0.5,
}
INPUT_SINKS = {"SQL_INJECTION", "CODE_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION",
               "TEMPLATE_INJECTION"}


def _scale(value: float, threshold: float, cap: float = 3.0) -> float:
    """0.5 at the threshold, rising to 1.0 at cap x threshold."""
    ratio = min(value / threshold, cap)
    return round(0.5 + 0.5 * (ratio - 1) / (cap - 1), 3)


class _Collector:
    def __init__(self, cg: CodeGraph):
        self.cg, self.out = cg, []

    def add(self, rule, category, sid, severity, confidence, msg, evidence, key=None,
            start=None, end=None, cwe=None):
        s = self.cg.symbols[sid]
        self.out.append(Finding(
            id="", rule=rule, category=category.value, symbol_id=sid, file=s.file,
            start_line=start or s.start_line, end_line=end or s.end_line,
            severity=round(severity, 3), confidence=round(confidence, 3), message=msg,
            key=key or f"{rule}:{sid}", cwe=cwe, evidence=evidence))


# ===================================================================== architecture
def _edge_users(cg: CodeGraph, src_mod: str, dst_mod: str) -> list[str]:
    """Which symbols in src_mod actually use something defined in dst_mod."""
    users = []
    for sid, s in cg.symbols.items():
        if s.module != src_mod:
            continue
        if any(cg.symbols[t].module == dst_mod for t in cg.uses(sid)):
            users.append(sid)
    return users


def architecture_rules(cg: CodeGraph, c: _Collector, t: Thresholds, lv: Liveness):
    live_mods = [m for m in cg.modules if m not in cg.test_modules]
    # --- import cycles: strongly connected components over real (top-level) imports
    hard = nx.DiGraph()
    hard.add_nodes_from(live_mods)
    for u, v, d in cg.mg.edges(data=True):
        if u in hard and v in hard and not d.get("lazy") and not d.get("type_only"):
            hard.add_edge(u, v, **d)
    for scc in nx.strongly_connected_components(hard):
        if len(scc) < 2:
            continue
        mods = sorted(scc)
        edges = []
        for u, v in hard.subgraph(scc).edges:
            users = _edge_users(cg, u, v)
            dead_only = bool(users) and all(x not in lv.live for x in users)
            edges.append({"src": u, "dst": v, "lines": hard.edges[u, v]["lines"], "users": users,
                          "unused_import": not users, "dead_users_only": dead_only})
        breakable = [e for e in edges if e["dead_users_only"] or e["unused_import"]]
        weakest = min(edges, key=lambda e: len(e["users"]))
        hint = (f"edge {breakable[0]['src']} -> {breakable[0]['dst']} is only used by dead code / unused; removing it breaks the cycle"
                if breakable else
                f"weakest edge {weakest['src']} -> {weakest['dst']} ({len(weakest['users'])} users): move those symbols or invert the dependency")
        anchor = (breakable[0]["src"] if breakable else weakest["src"])
        c.add("CYCLIC_DEPENDENCY", Category.ARCHITECTURE, f"{anchor}:",
              min(0.9, 0.6 + 0.05 * len(mods)), 0.9,
              f"import cycle between {len(mods)} modules: {' <-> '.join(mods)}",
              {"modules": mods, "edges": edges, "hint": hint},
              key="CYCLIC_DEPENDENCY:" + "|".join(mods), start=1, end=1)

    for m in live_mods:
        sid = f"{m}:"
        if sid not in cg.symbols:
            continue
        mt = cg.metrics(sid)
        loc, defs, cc = cg.symbols[sid].length, mt.get("num_defs", 0), mt.get("sum_complexity", 0)
        if loc > t.god_module_loc and (defs > t.god_module_defs or cc > t.god_module_cc):
            c.add("GOD_MODULE", Category.ARCHITECTURE, sid,
                  max(_scale(loc, t.god_module_loc), _scale(cc, t.god_module_cc)), 0.7,
                  f"{m}: {loc} lines, {defs} top-level definitions, total complexity {cc}",
                  {"loc": loc, "num_defs": defs, "sum_complexity": cc}, start=1, end=1)
        fin, fout = mt.get("imports_in", 0), mt.get("imports_out", 0)
        if fin >= t.hub_in and fout >= t.hub_out and not cg.modules[m].endswith("__init__.py"):
            c.add("HUB_MODULE", Category.ARCHITECTURE, sid, min(0.9, 0.4 + 0.04 * (fin + fout)), 0.6,
                  f"{m} is imported by {fin} modules and imports {fout}: a change here ripples both ways",
                  {"imports_in": fin, "imports_out": fout,
                   "dependents": sorted(cg.mg.predecessors(m)), "dependencies": sorted(cg.mg.successors(m))},
                  start=1, end=1)

    for sid, s in cg.symbols.items():
        if s.kind != SymbolKind.CLASS or s.is_test:
            continue
        m = cg.metrics(sid)
        nm, scc, cpl = m.get("num_methods", 0), m.get("sum_complexity", 0), m.get("coupling_out", 0)
        if sum([nm > t.god_methods, scc > t.god_sum_cc, cpl > t.god_coupling]) >= 2:
            c.add("GOD_CLASS", Category.ARCHITECTURE, sid,
                  max(_scale(nm, t.god_methods), _scale(scc, t.god_sum_cc), _scale(cpl, t.god_coupling)), 0.75,
                  f"{s.qualname}: {nm} methods, total complexity {scc}, depends on {cpl} other units",
                  {"num_methods": nm, "sum_complexity": scc, "coupling_out": cpl},
                  end=s.def_line)


# ===================================================================== smells
def smell_rules(cg: CodeGraph, c: _Collector, t: Thresholds):
    for sid, s in cg.symbols.items():
        if s.kind not in CODE_KINDS or s.is_test:
            continue
        if s.length > t.long_method_loc:
            c.add("LONG_METHOD", Category.SMELL, sid, _scale(s.length, t.long_method_loc), 0.8,
                  f"{s.qualname} is {s.length} lines (limit {t.long_method_loc})", {"loc": s.length})
        if s.complexity > t.complex_cc:
            c.add("COMPLEX_METHOD", Category.SMELL, sid, _scale(s.complexity, t.complex_cc), 0.85,
                  f"{s.qualname} has cyclomatic complexity {s.complexity} (limit {t.complex_cc})",
                  {"complexity": s.complexity})
        if s.num_params > t.long_params:
            c.add("LONG_PARAM_LIST", Category.SMELL, sid, _scale(s.num_params, t.long_params), 0.7,
                  f"{s.qualname} takes {s.num_params} parameters (limit {t.long_params})",
                  {"num_params": s.num_params, "params": s.params})
        if s.max_nesting > t.deep_nesting:
            c.add("DEEP_NESTING", Category.SMELL, sid, _scale(s.max_nesting, t.deep_nesting, cap=2), 0.85,
                  f"{s.qualname} nests blocks {s.max_nesting} levels deep (limit {t.deep_nesting})",
                  {"max_nesting": s.max_nesting})


# ===================================================================== security
def _const_at_call_sites(cg: CodeGraph, fid: str, used_params: list[str]) -> tuple[bool, int]:
    """True if every resolved call into `fid` passes a constant for every param the sink uses."""
    f = cg.symbols[fid]
    n_sites, all_const = 0, True
    for caller in cg.callers(fid):
        for site in cg.symbols[caller].call_sites:
            if cg._resolve(cg.symbols[caller], site["name"]) != fid:
                continue
            n_sites += 1
            for p in used_params:
                i = f.params.index(p) if p in f.params else -1
                if p in site["const_kwargs"]:
                    ok = site["const_kwargs"][p]
                elif 0 <= i < len(site["const_args"]):
                    ok = site["const_args"][i]
                else:
                    ok = True                       # not passed -> its default value is used
                all_const &= ok
    return (n_sites > 0 and all_const), n_sites


def security_rules(cg: CodeGraph, c: _Collector, lv: Liveness):
    tainted = {sid for sid, s in cg.symbols.items() if s.taint_sources}
    seen = set()
    for sid, s in cg.symbols.items():
        if s.is_test or not s.security_hits:
            continue
        counts: dict[str, int] = {}
        for h in s.security_hits:
            dedup = (s.file, h["line"], h["call"])
            if dedup in seen:
                continue
            seen.add(dedup)
            rule = h["rule"]
            ev = dict(h)
            ev["mode"] = lv.mode
            sev = SECURITY_SEVERITY[rule]
            conf = 0.6
            if rule in INPUT_SINKS:
                if h["constant_args"]:
                    conf, ev["taint"] = 0.25, "constant argument: no outside data can reach this sink"
                elif s.taint_sources:
                    conf = 0.95
                    ev["taint"] = "direct: this function reads " + ", ".join(x["source"] for x in s.taint_sources)
                    ev["taint_path"] = [sid]
                elif h["uses_params"]:
                    const, n = _const_at_call_sites(cg, sid, h["uses_params"])
                    path = cg.shortest_path(tainted, sid, kinds=("calls",))
                    if const:
                        conf = 0.3
                        ev["taint"] = f"all {n} call site(s) pass constants for {h['uses_params']}"
                    elif path:
                        conf = 0.85
                        src = cg.symbols[path[0]].taint_sources
                        ev["taint"] = f"user input ({', '.join(x['source'] for x in src)}) reaches it through callers"
                        ev["taint_path"] = path
                    else:
                        conf = 0.6
                        ev["taint"] = f"parameters {h['uses_params']} reach the sink; no user-input source found in callers"
                else:
                    conf = 0.55
                    ev["taint"] = "data source unclear (not a parameter, not a constant)"
            elif rule == "HARDCODED_SECRET":
                conf = 0.3 if h.get("looks_like_url") else 0.8
            if sid not in lv.live and s.kind != SymbolKind.MODULE:
                ev["in_dead_code"] = True
                conf *= 0.8
            counts[h["call"]] = counts.get(h["call"], 0) + 1
            key = f"{rule}:{sid}:{h['call']}" + (f"#{counts[h['call']]}" if counts[h["call"]] > 1 else "")
            where = s.qualname or s.module
            c.add(rule, Category.SECURITY, sid, sev, conf,
                  f"{h['call'] + ('' if rule == 'HARDCODED_SECRET' else '()')} in {where}, line {h['line']}: "
                  f"{h['reason']} ({h['cwe']})",
                  ev, key=key, start=h["line"], end=h["line"], cwe=h["cwe"])


# ===================================================================== dead code
def dead_code_rules(cg: CodeGraph, c: _Collector, lv: Liveness):
    for m in lv.unused_modules:
        sid = f"{m}:"
        if sid in cg.symbols:
            c.add("UNUSED_MODULE", Category.DEAD_CODE, sid, 0.5, 0.75,
                  f"module {m} is never imported and is not an entry point",
                  {"entry_modules": lv.entry_modules[:10]}, key=f"UNUSED_MODULE:{m}", start=1, end=1)
    for d in lv.dead:
        sid = d["symbol_id"]
        s = cg.symbols[sid]
        conf = 0.85
        why = "no call or reference reaches it from any entry point"
        if d["transitive"]:
            names = ", ".join(cg.symbols[u].qualname or u for u in d["users"][:3])
            why = f"only used by code that is itself dead ({names})"
        if d["possibly_dynamic"]:
            conf = 0.35
        c.add("DEAD_CODE", Category.DEAD_CODE, sid, 0.45 + min(0.3, s.length / 200), conf,
              f"{s.kind.value} {s.qualname} is unreachable: {why}",
              {"users": d["users"], "transitive": d["transitive"],
               "possibly_dynamic": d["possibly_dynamic"], "loc": s.length, "mode": lv.mode})


# ===================================================================== entry
def run_rules(cg: CodeGraph, t: Thresholds | None = None, mode: str = "auto",
              liveness: Liveness | None = None) -> tuple[list[Finding], Liveness]:
    t = t or Thresholds()
    lv = liveness or analyze_liveness(cg, mode)
    c = _Collector(cg)
    architecture_rules(cg, c, t, lv)
    security_rules(cg, c, lv)
    dead_code_rules(cg, c, lv)
    smell_rules(cg, c, t)
    for i, f in enumerate(c.out, 1):
        f.id = f"F{i:03d}"
    return c.out, lv
