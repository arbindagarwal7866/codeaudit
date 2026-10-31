"""
Shared data contracts. Every stage imports from here.

  ingest/parse/graph  -> FileRecord, Symbol, Edge
  rules/deadcode      -> Finding
  context             -> ContextBundle  (what an LLM agent is allowed to see)
  agents              -> fill Finding.llm_verdict, produce analysis / patches
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class SymbolKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"


class EdgeKind(str, Enum):
    CONTAINS = "contains"       # module -> class, class -> method
    CALLS = "calls"             # function -> function / class (instantiation)
    REFERENCES = "references"   # function used as a value: callback, registry, decorator
    IMPORTS = "imports"         # module -> module
    INHERITS = "inherits"       # class -> base class


class Category(str, Enum):
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    DEAD_CODE = "dead_code"
    SMELL = "smell"


@dataclass
class FileRecord:
    path: str               # relative to repo root, e.g. "pkg/utils.py"
    module: str             # dotted name, e.g. "pkg.utils"
    sha1: str
    loc: int                # physical lines
    is_test: bool = False   # tests count as entry points but are never audited


@dataclass
class Symbol:
    id: str                 # globally unique: "pkg.utils:Parser.parse"  (module itself: "pkg.utils:")
    name: str
    qualname: str
    kind: SymbolKind
    file: str
    module: str
    start_line: int         # first decorator line if decorated
    end_line: int
    def_line: int = 0       # the `def`/`class` line itself
    complexity: int = 1
    num_params: int = 0
    params: list[str] = field(default_factory=list)
    max_nesting: int = 0
    docstring: Optional[str] = None
    raw_calls: list[str] = field(default_factory=list)       # unresolved call names
    raw_refs: list[str] = field(default_factory=list)        # names used as values
    call_sites: list[dict] = field(default_factory=list)     # {name, line, const_args, const_kwargs}
    bases: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    taint_sources: list[dict] = field(default_factory=list)  # {source, line}
    security_hits: list[dict] = field(default_factory=list)  # see parse.security_hits
    is_test: bool = False
    # module-only facts
    has_main_guard: bool = False
    exports: list[str] = field(default_factory=list)         # __all__
    dynamic_prefixes: list[str] = field(default_factory=list)  # getattr(x, "handle_" + y)

    @property
    def length(self) -> int:
        return self.end_line - self.start_line + 1


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind


@dataclass
class Finding:
    id: str
    rule: str                   # e.g. "SQL_INJECTION", "CYCLIC_DEPENDENCY", "DEAD_CODE"
    category: str               # Category value
    symbol_id: str
    file: str
    start_line: int
    end_line: int
    severity: float             # 0..1 how bad if real
    confidence: float           # 0..1 how sure the static rule is
    message: str
    key: str = ""               # stable id across runs (for labels/evaluation)
    cwe: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    priority: float = 0.0
    llm_verdict: Optional[str] = None


@dataclass
class ContextBundle:
    """Exactly what an LLM agent receives about one finding. Built from the graph, never the whole repo."""
    target_id: str
    target_source: str
    finding_summary: str = ""
    facts: list[str] = field(default_factory=list)          # graph facts: entry path, taint path, blast radius...
    callers: list[dict] = field(default_factory=list)       # {id, file, source}
    callees: list[dict] = field(default_factory=list)
    related: list[dict] = field(default_factory=list)       # cycle-edge users, etc.
    siblings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    approx_tokens: int = 0

    def to_prompt(self) -> str:
        parts = []
        if self.finding_summary:
            parts += ["## Finding", self.finding_summary]
        if self.facts:
            parts += ["## Repository facts (from the dependency graph)"] + [f"- {f}" for f in self.facts]
        parts += [f"## Target: {self.target_id}", f"Metrics: {self.metrics}",
                  "```python", self.target_source, "```"]
        if self.imports:
            parts += ["## Module imports", "\n".join(self.imports)]
        if self.siblings:
            parts += ["## Sibling members (signatures)", "\n".join(self.siblings)]
        for title, items in (("Callers", self.callers), ("Callees", self.callees),
                             ("Related code", self.related)):
            if items:
                parts.append(f"## {title}")
                for it in items:
                    parts += [f"# {it['id']} ({it['file']})", "```python", it["source"], "```"]
        return "\n".join(parts)


def to_dict(obj) -> dict:
    d = asdict(obj)
    for k, v in d.items():
        if isinstance(v, Enum):
            d[k] = v.value
    return d
