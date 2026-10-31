"""Stage 3: the Dependency Graph.

Two views of the repository:
  g   symbol graph (MultiDiGraph): contains / calls / references / inherits edges
  mg  module graph (DiGraph): module -> module import edges (toplevel / lazy / type-only)

Everything later (dead code, cycles, taint paths, ranking, LLM context) is a query on these.
"""
from __future__ import annotations
import builtins
import json
from collections import Counter, deque
from functools import lru_cache
from pathlib import Path
import networkx as nx

from .ingest import ingest
from .parse import parse_file
from .models import Symbol, SymbolKind, EdgeKind, to_dict

CODE_KINDS = (SymbolKind.FUNCTION, SymbolKind.METHOD)


class CodeGraph:
    def __init__(self, repo_root: str):
        self.repo_root = str(Path(repo_root).resolve())
        self.g = nx.MultiDiGraph()
        self.mg = nx.DiGraph()
        self.symbols: dict[str, Symbol] = {}
        self.imports: dict[str, dict[str, str]] = {}      # module -> {alias: fq target}
        self.modules: dict[str, str] = {}                  # module -> file path
        self.test_modules: set[str] = set()
        self.attrs: set[str] = set()                       # every obj.<attr> name seen anywhere
        self.strings: set[str] = set()                     # identifier-like string literals
        self.parse_errors: dict[str, str] = {}
        self.unresolved: Counter = Counter()
        self.external_calls = 0
        self._by_mq: dict[tuple[str, str], str] = {}
        self._import_recs: dict[str, list] = {}
        self._file_cache: dict[str, list[str]] = {}

    # ================================================================ build
    @classmethod
    def build(cls, repo_root: str) -> "CodeGraph":
        cg = cls(repo_root)
        for rec in ingest(repo_root):
            if rec.module in cg.modules:                    # duplicate dotted name: keep both
                rec.module = rec.path[:-3].replace("/", ".")
            pf = parse_file(repo_root, rec)
            if pf.error:
                cg.parse_errors[rec.path] = pf.error
                continue
            cg.modules[rec.module] = rec.path
            if rec.is_test:
                cg.test_modules.add(rec.module)
            cg.imports[rec.module] = {r.alias: r.target for r in pf.imports if r.alias}
            cg._import_recs[rec.module] = pf.imports
            cg.attrs |= pf.attrs
            cg.strings |= pf.strings
            for s in pf.symbols:
                cg.symbols[s.id] = s
                cg._by_mq[(s.module, s.qualname)] = s.id
                cg.g.add_node(s.id, kind=s.kind.value)
        cg._link()
        return cg

    def _link(self):
        for m, path in self.modules.items():
            self.mg.add_node(m, file=path)
        self._add_contains_edges()
        self._add_import_edges()
        self._add_inherit_edges()
        self._add_call_and_ref_edges()
        self._compute_metrics()

    def _edge(self, src, dst, kind: EdgeKind, **attrs):
        if src != dst and not self.g.has_edge(src, dst, key=kind.value):
            self.g.add_edge(src, dst, key=kind.value, kind=kind.value, **attrs)

    def _add_contains_edges(self):
        for s in self.symbols.values():
            if s.kind == SymbolKind.MODULE:
                continue
            parent_q = s.qualname.rsplit(".", 1)[0] if "." in s.qualname else ""
            parent = self._by_mq.get((s.module, parent_q))
            if parent:
                self._edge(parent, s.id, EdgeKind.CONTAINS)

    # ---------------------------------------------------------------- name resolution
    def _split_fq(self, fq: str) -> tuple[str, str] | None:
        """'pkg.mod.Cls.meth' -> ('pkg.mod', 'Cls.meth') using the longest known module."""
        parts = fq.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            if mod in self.modules:
                return mod, ".".join(parts[i:])
        return None

    def _lookup_fq(self, fq: str, depth: int = 0) -> str | None:
        split = self._split_fq(fq)
        if not split:
            return None
        if split in self._by_mq:
            return self._by_mq[split]
        mod, qual = split
        head, _, rest = qual.partition(".")
        reexp = self.imports.get(mod, {}).get(head)          # follow re-exports
        if reexp and depth < 4:
            return self._lookup_fq(reexp + ("." + rest if rest else ""), depth + 1)
        return None

    def _fq_is_external(self, fq: str, depth: int = 0) -> bool:
        split = self._split_fq(fq)
        if not split:
            return True
        mod, qual = split
        reexp = self.imports.get(mod, {}).get(qual.partition(".")[0])
        return bool(reexp) and depth < 4 and self._fq_is_external(reexp, depth + 1)

    def _resolve_name(self, module: str, name: str) -> str | None:
        if (module, name) in self._by_mq:
            return self._by_mq[(module, name)]
        head, _, rest = name.partition(".")
        if (module, head) in self._by_mq and rest:            # Cls.method used inside module
            return self._by_mq.get((module, name))
        imps = self.imports.get(module, {})
        if head in imps:
            return self._lookup_fq(imps[head] + ("." + rest if rest else ""))
        return None

    def enclosing_class(self, s: Symbol) -> str | None:
        parts = s.qualname.split(".")
        for i in range(len(parts) - 1, 0, -1):
            cid = self._by_mq.get((s.module, ".".join(parts[:i])))
            if cid and self.symbols[cid].kind == SymbolKind.CLASS:
                return cid
        return None

    def method_in_hierarchy(self, class_id: str, meth: str, depth=0) -> str | None:
        c = self.symbols[class_id]
        mid = self._by_mq.get((c.module, f"{c.qualname}.{meth}"))
        if mid or depth > 6:
            return mid
        for base in self.bases(class_id):
            found = self.method_in_hierarchy(base, meth, depth + 1)
            if found:
                return found
        return None

    def _resolve(self, s: Symbol, name: str) -> str | None:
        head, _, rest = name.partition(".")
        if head in ("self", "cls") and rest and "." not in rest:
            cid = self.enclosing_class(s)
            return self.method_in_hierarchy(cid, rest) if cid else None
        if s.qualname:
            nested = self._by_mq.get((s.module, f"{s.qualname}.{name}"))
            if nested:
                return nested
            cid = self.enclosing_class(s) if s.kind == SymbolKind.METHOD else None
            if s.kind == SymbolKind.CLASS:
                cid = s.id
            if cid and "." not in name:                       # class-body reference to a method
                m = self._by_mq.get((s.module, f"{self.symbols[cid].qualname}.{name}"))
                if m and s.kind == SymbolKind.CLASS:
                    return m
        tgt = self._resolve_name(s.module, name)
        if tgt is None and "." in name:                        # ClassName.method / module.func
            tgt = self._resolve_name(s.module, name.rsplit(".", 1)[0])
            if tgt and self.symbols[tgt].kind == SymbolKind.CLASS:
                tgt = self.method_in_hierarchy(tgt, name.rsplit(".", 1)[1]) or None
            elif tgt and self.symbols[tgt].kind == SymbolKind.MODULE:
                tgt = None
            else:
                tgt = None
        return tgt

    # ---------------------------------------------------------------- edges
    def _add_import_edges(self):
        for mod, recs in self._import_recs.items():
            for r in recs:
                split = self._split_fq(r.target)
                if not split or split[0] == mod:
                    continue
                dst = split[0]
                lazy, typ = r.kind == "lazy", r.kind == "type"
                if self.mg.has_edge(mod, dst):
                    e = self.mg.edges[mod, dst]
                    e["lazy"] = e["lazy"] and lazy           # toplevel wins
                    e["type_only"] = e["type_only"] and typ
                    e["lines"] = sorted(set(e["lines"] + [r.line]))
                else:
                    self.mg.add_edge(mod, dst, lazy=lazy, type_only=typ, lines=[r.line])
                self._edge(f"{mod}:", f"{dst}:", EdgeKind.IMPORTS)

    def _add_inherit_edges(self):
        for s in self.symbols.values():
            if s.kind == SymbolKind.CLASS:
                for b in s.bases:
                    tgt = self._resolve_name(s.module, b)
                    if tgt and self.symbols[tgt].kind == SymbolKind.CLASS:
                        self._edge(s.id, tgt, EdgeKind.INHERITS)

    def _is_external(self, module: str, call: str) -> bool:
        head = call.split(".")[0]
        if "." not in call and hasattr(builtins, head):
            return True
        tgt = self.imports.get(module, {}).get(head)
        return tgt is not None and self._fq_is_external(tgt)

    def _add_call_and_ref_edges(self):
        for s in list(self.symbols.values()):
            for call in s.raw_calls:
                tgt = self._resolve(s, call)
                if tgt:
                    self._edge(s.id, tgt, EdgeKind.CALLS)
                elif self._is_external(s.module, call):
                    self.external_calls += 1
                else:
                    self.unresolved[call] += 1
            for ref in s.raw_refs:
                tgt = self._resolve(s, ref)
                if tgt and self.symbols[tgt].kind != SymbolKind.MODULE:
                    self._edge(s.id, tgt, EdgeKind.REFERENCES)

    # ================================================================ queries
    def _nbrs(self, nid, kinds, out=True):
        edges = self.g.out_edges(nid, keys=True) if out else self.g.in_edges(nid, keys=True)
        res = [(v if out else u) for u, v, k in edges if k in kinds]
        return list(dict.fromkeys(res))

    def callers(self, nid):  return self._nbrs(nid, ("calls",), out=False)
    def callees(self, nid):  return self._nbrs(nid, ("calls",), out=True)
    def users(self, nid):    return self._nbrs(nid, ("calls", "references"), out=False)
    def uses(self, nid):     return self._nbrs(nid, ("calls", "references"), out=True)
    def members(self, nid):  return self._nbrs(nid, ("contains",), out=True)
    def bases(self, nid):    return self._nbrs(nid, ("inherits",), out=True)
    def subclasses(self, nid): return self._nbrs(nid, ("inherits",), out=False)
    def metrics(self, nid):  return self.g.nodes[nid].get("metrics", {})

    def parent(self, nid):
        p = self._nbrs(nid, ("contains",), out=False)
        return p[0] if p else None

    def module_sym(self, nid) -> str:
        return f"{self.symbols[nid].module}:"

    def lines(self, rel_path: str) -> list[str]:
        if rel_path not in self._file_cache:
            self._file_cache[rel_path] = (Path(self.repo_root) / rel_path).read_text(
                encoding="utf-8", errors="replace").splitlines()
        return self._file_cache[rel_path]

    def source(self, nid: str, max_lines: int = 400) -> str:
        s = self.symbols[nid]
        ls = self.lines(s.file)[s.start_line - 1: s.end_line]
        if len(ls) > max_lines:
            ls = ls[:max_lines] + [f"# ... {len(ls) - max_lines} more lines"]
        return "\n".join(ls)

    @lru_cache(maxsize=None)
    def blast_radius(self, nid: str) -> int:
        """How many functions/classes depend on this one, directly or transitively."""
        seen, q = {nid}, deque([nid])
        while q:
            for u in self.users(q.popleft()):
                if u not in seen and self.symbols[u].kind != SymbolKind.MODULE:
                    seen.add(u); q.append(u)
        return len(seen) - 1

    def shortest_path(self, sources: set[str], target: str, kinds=("calls", "references"),
                      max_depth: int = 8) -> list[str] | None:
        """BFS backwards from target until any source is hit; returns source -> ... -> target."""
        if target in sources:
            return [target]
        prev, q = {target: None}, deque([(target, 0)])
        while q:
            n, d = q.popleft()
            if d >= max_depth:
                continue
            for u in self._nbrs(n, kinds, out=False):
                if u in prev:
                    continue
                prev[u] = n
                if u in sources:
                    path = [u]
                    while path[-1] != target:
                        path.append(prev[path[-1]])
                    return path
                q.append((u, d + 1))
        return None

    def module_pagerank(self, damping: float = 0.85, iters: int = 50) -> dict[str, float]:
        """Importance of each module: depended on by important modules -> important."""
        nodes = list(self.mg.nodes)
        if not nodes:
            return {}
        n = len(nodes)
        pr = {m: 1 / n for m in nodes}
        out_deg = {m: self.mg.out_degree(m) for m in nodes}
        for _ in range(iters):
            dangling = sum(pr[m] for m in nodes if out_deg[m] == 0)
            new = {}
            for m in nodes:
                inc = sum(pr[u] / out_deg[u] for u in self.mg.predecessors(m))
                new[m] = (1 - damping) / n + damping * (inc + dangling / n)
            pr = new
        return pr

    # ================================================================ metrics
    def _compute_metrics(self):
        pr = self.module_pagerank()
        top = max(pr.values(), default=1) or 1
        for nid in self.g.nodes:
            s = self.symbols[nid]
            m = {"fan_in": len(self.users(nid)), "fan_out": len(self.uses(nid)),
                 "loc": s.length, "complexity": s.complexity, "num_params": s.num_params,
                 "max_nesting": s.max_nesting}
            if s.kind == SymbolKind.CLASS:
                members = [x for x in self.members(nid) if self.symbols[x].kind == SymbolKind.METHOD]
                m["num_methods"] = len(members)
                ext = set()
                for mid in members:
                    for callee in self.uses(mid):
                        cs = self.symbols[callee]
                        owner = (callee if cs.kind == SymbolKind.CLASS else self.enclosing_class(cs)) \
                            or f"{cs.module}:"
                        if owner != nid:
                            ext.add(owner)
                m["coupling_out"] = len(ext)
                m["sum_complexity"] = sum(self.symbols[x].complexity for x in members)
            if s.kind == SymbolKind.MODULE and s.module in self.mg:
                defs = [x for x in self.members(nid)]
                m["imports_out"] = self.mg.out_degree(s.module)
                m["imports_in"] = self.mg.in_degree(s.module)
                m["num_defs"] = len(defs)
                m["sum_complexity"] = sum(self.symbols[x].complexity for x in self.symbols
                                          if self.symbols[x].module == s.module
                                          and self.symbols[x].kind in CODE_KINDS)
                m["pagerank"] = round(pr.get(s.module, 0) / top, 3)
            self.g.nodes[nid]["metrics"] = m

    def centrality(self, nid: str) -> float:
        """0..1 importance of the module this symbol lives in."""
        return self.metrics(self.module_sym(nid)).get("pagerank", 0.0)

    def stats(self) -> dict:
        kinds = Counter(d["kind"] for _, d in self.g.nodes(data=True))
        ekinds = Counter(k for _, _, k in self.g.edges(keys=True))
        resolved = ekinds.get("calls", 0)
        total = resolved + sum(self.unresolved.values())
        return {
            "files": len(self.modules), "test_files": len(self.test_modules),
            "nodes": dict(kinds), "edges": dict(ekinds),
            "module_edges": self.mg.number_of_edges(),
            "parse_errors": len(self.parse_errors),
            "external_calls": self.external_calls,
            "unresolved_calls": sum(self.unresolved.values()),
            "call_resolution_rate": round(resolved / total, 3) if total else 0,
        }

    # ================================================================ persistence
    def save(self, path: str):
        data = {
            "repo_root": self.repo_root,
            "modules": self.modules, "test_modules": sorted(self.test_modules),
            "imports": self.imports,
            "symbols": [to_dict(s) for s in self.symbols.values()],
            "edges": [{"src": u, "dst": v, "kind": k} for u, v, k in self.g.edges(keys=True)],
            "module_edges": [{"src": u, "dst": v, **d} for u, v, d in self.mg.edges(data=True)],
            "metrics": {n: self.metrics(n) for n in self.g.nodes},
            "attrs": sorted(self.attrs), "strings": sorted(self.strings),
            "parse_errors": self.parse_errors, "stats": self.stats(),
        }
        Path(path).write_text(json.dumps(data, indent=1), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "CodeGraph":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cg = cls(data["repo_root"])
        cg.modules = data["modules"]
        cg.test_modules = set(data["test_modules"])
        cg.imports = data["imports"]
        cg.attrs, cg.strings = set(data["attrs"]), set(data["strings"])
        cg.parse_errors = data.get("parse_errors", {})
        for d in data["symbols"]:
            d["kind"] = SymbolKind(d["kind"])
            s = Symbol(**d)
            cg.symbols[s.id] = s
            cg._by_mq[(s.module, s.qualname)] = s.id
            cg.g.add_node(s.id, kind=s.kind.value, metrics=data["metrics"].get(s.id, {}))
        for e in data["edges"]:
            cg.g.add_edge(e["src"], e["dst"], key=e["kind"], kind=e["kind"])
        for m, p in cg.modules.items():
            cg.mg.add_node(m, file=p)
        for e in data["module_edges"]:
            cg.mg.add_edge(e.pop("src"), e.pop("dst"), **e)
        return cg
