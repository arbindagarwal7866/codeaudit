"""Evaluation — the project's measurable result.

Question: does the agent triage make static analysis more precise without losing real issues?

Ground truth = a CSV labelled by a human:  key, label, note
  TP  the finding is a real problem
  FP  the finding is a false alarm
  FN  a real problem the static rules did NOT find (key describes it) -> counts against recall

  precision = real issues reported / everything reported      ("how much of the list is worth reading")
  recall    = real issues reported / all real issues           ("how much did we catch")
  F1        = harmonic mean of the two
"""
from __future__ import annotations
import csv
import json

from .context import build_context
from .graph import CodeGraph
from .rank import rank
from .rules import run_rules


def load_labels(path: str) -> dict[str, dict]:
    labels = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            lab = (row.get("label") or "").strip().upper()
            if lab in ("TP", "FP", "FN") and row.get("key"):
                labels[row["key"].strip()] = {"label": lab, "note": row.get("note", ""), "rule": row.get("rule", "")}
    return labels


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn}


def score(rows: list[tuple[str, str, str]], missed: int) -> dict:
    """rows = (label TP/FP, verdict TRUE_POSITIVE/FALSE_POSITIVE/None, category)."""
    real = sum(1 for lab, _, _ in rows if lab == "TP")
    before = _prf(real, len(rows) - real, missed)
    kept = [(lab, c) for lab, v, c in rows if v in (None, "TRUE_POSITIVE")]
    kept_real = sum(1 for lab, _ in kept if lab == "TP")
    after = _prf(kept_real, len(kept) - kept_real, missed + (real - kept_real))
    per_cat = {}
    for lab, v, c in rows:
        d = per_cat.setdefault(c, {"findings": 0, "real": 0, "kept": 0, "kept_real": 0})
        d["findings"] += 1
        d["real"] += lab == "TP"
        d["kept"] += v in (None, "TRUE_POSITIVE")
        d["kept_real"] += lab == "TP" and v in (None, "TRUE_POSITIVE")
    return {
        "labelled_findings": len(rows), "missed_by_rules": missed,
        "before_triage": before, "after_triage": after,
        "false_positives_removed": before["fp"] - after["fp"],
        "real_issues_wrongly_dismissed": real - kept_real,
        "per_category": per_cat,
    }


def evaluate_data(data: dict, labels_path: str) -> dict:
    labels = load_labels(labels_path)
    rows, unlabeled, mistakes = [], [], []
    keys_found = set()
    for r in data["results"]:
        f = r["finding"]
        keys_found.add(f["key"])
        lab = labels.get(f["key"])
        if not lab or lab["label"] == "FN":
            unlabeled.append(f["key"])
            continue
        v = r.get("triage", {}).get("verdict")
        rows.append((lab["label"], v, f["category"]))
        if v and (v == "TRUE_POSITIVE") != (lab["label"] == "TP"):
            mistakes.append({"key": f["key"], "label": lab["label"], "verdict": v,
                             "reason": r["triage"].get("reason", "")})
    missed = [k for k, v in labels.items() if v["label"] == "FN" and k not in keys_found]
    out = score(rows, len(missed))
    out.update({"triage_mode": data["summary"]["llm"], "unlabelled": unlabeled,
                "missed": missed, "triage_mistakes": mistakes})
    return out


def evaluate(results_path: str, labels_path: str) -> dict:
    return evaluate_data(json.loads(open(results_path, encoding="utf-8").read()), labels_path)


def compare_triage(repo: str, labels_path: str, llms: list, mode: str = "auto", log=print) -> list[dict]:
    """Same findings, same labels, different triage agents (heuristic vs one or more LLMs)."""
    from .agents.triage import triage
    from .deadcode import analyze_liveness
    cg = CodeGraph.build(repo)
    lv = analyze_liveness(cg, mode)
    findings, _ = run_rules(cg, mode=mode, liveness=lv)
    findings = rank(cg, findings)
    labels = load_labels(labels_path)
    missed = sum(1 for k, v in labels.items() if v["label"] == "FN" and k not in {f.key for f in findings})
    table = []
    static_rows = [(labels[f.key]["label"], None, f.category) for f in findings
                   if f.key in labels and labels[f.key]["label"] != "FN"]
    table.append({"agent": "static rules only (no triage)", **score(static_rows, missed)["before_triage"]})
    for llm in llms:
        rows, mistakes = [], []
        for f in findings:
            lab = labels.get(f.key)
            if not lab or lab["label"] == "FN":
                continue
            ctx = build_context(cg, f, lv.entry_symbols)
            v = triage(llm, cg, f, ctx, lv.mode)
            rows.append((lab["label"], v["verdict"], f.category))
            if (v["verdict"] == "TRUE_POSITIVE") != (lab["label"] == "TP"):
                mistakes.append(f.key)
        s = score(rows, missed)
        table.append({"agent": llm.label, **s["after_triage"], "mistakes": mistakes,
                      "usage": None if llm.offline else llm.usage()})
        log(f"{llm.label}: precision {s['after_triage']['precision']} recall {s['after_triage']['recall']}")
    return table
