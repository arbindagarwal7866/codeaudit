"""
Stage 5: Ranking — which findings are worth the (slow, paid) LLM?

  priority = severity x confidence x category_weight x (1 + centrality) x (1 + 0.15 * log2(1 + blast_radius))

  severity     how bad if real            (rule)
  confidence   how sure the static rule is (taint path, constant args, dynamic names ...)
  centrality   PageRank of the module in the import graph (0..1): core modules matter more
  blast_radius how many functions depend on this one, directly or transitively

Findings are renumbered F001, F002 ... in priority order. Only the top-K go to the agents.
"""
from __future__ import annotations
import math
from .graph import CodeGraph
from .models import Finding

CATEGORY_WEIGHT = {"security": 1.5, "architecture": 1.2, "dead_code": 1.0, "smell": 0.9}


def priority(cg: CodeGraph, f: Finding) -> float:
    blast = cg.blast_radius(f.symbol_id)
    centrality = cg.centrality(f.symbol_id)
    f.evidence["blast_radius"] = blast
    f.evidence["centrality"] = centrality
    return round(f.severity * f.confidence * CATEGORY_WEIGHT.get(f.category, 1.0)
                 * (1 + centrality) * (1 + 0.15 * math.log2(1 + blast)), 3)


def rank(cg: CodeGraph, findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.priority = priority(cg, f)
    ranked = sorted(findings, key=lambda f: (-f.priority, f.key))
    for i, f in enumerate(ranked, 1):
        f.id = f"F{i:03d}"
    return ranked
