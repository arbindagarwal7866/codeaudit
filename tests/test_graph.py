from codeaudit.context import build_context
from codeaudit.graph import CodeGraph
from codeaudit.ingest import is_remote, path_to_module
from codeaudit.parse import parse_source, security_hits
from codeaudit.models import FileRecord
from codeaudit.rules import run_rules
from pathlib import Path
import ast

from conftest import FIXTURE, SHOPKART


def test_symbols_and_cross_module_calls():
    cg = CodeGraph.build(str(FIXTURE))
    for sid in ["shop.cart:Cart", "shop.cart:Cart.add", "shop.utils:fmt_price", "shop.pricing:discount"]:
        assert sid in cg.symbols
    assert "shop.utils:fmt_price" in cg.callees("shop.cart:Cart.total")      # relative import resolved
    assert "shop.cart:Base.log" in cg.callees("shop.cart:Cart.add")          # self.call through inheritance


def test_complexity_and_nesting():
    cg = CodeGraph.build(str(FIXTURE))
    assert cg.symbols["shop.cart:Cart.add"].complexity == 3                  # 1 + if + `or`
    assert cg.symbols["shop.pricing:discount"].max_nesting == 5


def test_module_graph_cycle_and_lazy_flags():
    cg = CodeGraph.build(str(SHOPKART))
    assert cg.mg.has_edge("shopkart.orders", "shopkart.inventory")
    assert cg.mg.has_edge("shopkart.inventory", "shopkart.orders")
    assert not cg.mg.edges["shopkart.orders", "shopkart.inventory"]["lazy"]
    pr = cg.module_pagerank()
    assert abs(sum(pr.values()) - 1) < 1e-6


def test_references_are_edges():
    rec = FileRecord("m.py", "m", "x", 5)
    pf = parse_source(rec, "def a():\n    return 1\n\ndef b():\n    return list(map(a, [1]))\n")
    b = next(s for s in pf.symbols if s.name == "b")
    assert "a" in b.raw_refs                                                  # passed as a callback


def test_taint_and_sinks_detected():
    src = ("import sys\n\ndef f(x):\n    q = 'SELECT * FROM t WHERE a = ' + x\n    cur.execute(q)\n"
           "    eval('1+1')\n    return sys.argv\n")
    fn = ast.parse(src).body[1]
    hits = security_hits(fn, ["x"])
    sql = next(h for h in hits if h["rule"] == "SQL_INJECTION")
    assert sql["uses_params"] == ["x"] and sql["constant_args"] is False      # followed q = ... + x
    ev = next(h for h in hits if h["rule"] == "CODE_INJECTION")
    assert ev["constant_args"] is True


def test_blast_radius_and_paths():
    cg = CodeGraph.build(str(SHOPKART))
    assert cg.blast_radius("shopkart.db:get_user") >= 2
    path = cg.shortest_path({"app:main"}, "shopkart.db:get_user")
    assert path == ["app:main", "app:handle", "shopkart.db:get_user"]


def test_save_load_roundtrip(tmp_path):
    cg = CodeGraph.build(str(SHOPKART))
    cg.save(str(tmp_path / "g.json"))
    cg2 = CodeGraph.load(str(tmp_path / "g.json"))
    assert set(cg2.g.edges(keys=True)) == set(cg.g.edges(keys=True))
    assert set(cg2.mg.edges) == set(cg.mg.edges)


def test_context_is_small_and_graph_based():
    cg = CodeGraph.build(str(SHOPKART))
    findings, lv = run_rules(cg)
    f = next(x for x in findings if x.key == "SQL_INJECTION:shopkart.db:get_user:cur.execute")
    b = build_context(cg, f, lv.entry_symbols)
    text = b.to_prompt()
    assert "main -> handle -> get_user" in text and "def handle" in text
    repo_chars = sum(len(l) for p in cg.modules.values() for l in cg.lines(p))
    assert len(text) < repo_chars / 3


def test_ingest_helpers():
    assert is_remote("https://github.com/psf/requests") and not is_remote("examples/shopkart")
    assert path_to_module(Path("src/pkg/mod.py")) == "pkg.mod"
    assert path_to_module(Path("pkg/__init__.py")) == "pkg"
