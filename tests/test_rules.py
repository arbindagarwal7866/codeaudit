import csv

from codeaudit.graph import CodeGraph
from codeaudit.rank import rank
from codeaudit.rules import run_rules

from conftest import LABELS, SHOPKART, FIXTURE


def _findings():
    cg = CodeGraph.build(str(SHOPKART))
    fs, lv = run_rules(cg)
    return cg, rank(cg, fs), lv


def test_every_labelled_issue_is_found_except_the_known_miss():
    _, fs, _ = _findings()
    keys = {f.key for f in fs}
    with open(LABELS) as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        if r["label"] in ("TP", "FP"):
            assert r["key"] in keys, r["key"]
        else:
            assert r["key"] not in keys                       # FN = honest known miss


def test_cycle_edge_used_only_by_dead_code():
    _, fs, _ = _findings()
    cyc = next(f for f in fs if f.rule == "CYCLIC_DEPENDENCY")
    edge = next(e for e in cyc.evidence["edges"] if e["src"] == "shopkart.inventory")
    assert edge["dead_users_only"] and edge["users"] == ["shopkart.inventory:restock_value"]


def test_dead_code_is_reachability_not_linting():
    _, fs, lv = _findings()
    dead = {f.symbol_id: f for f in fs if f.rule == "DEAD_CODE"}
    assert dead["shopkart.inventory:_to_xml"].evidence["transitive"]          # only used by dead code
    assert dead["shopkart.plugins:Actions.handle_refund"].evidence["possibly_dynamic"]
    assert "shopkart.inventory:check_stock" not in dead                       # used -> alive
    assert lv.unused_modules == ["shopkart.legacy"]


def test_taint_path_and_constant_call_sites():
    _, fs, _ = _findings()
    by = {f.key: f for f in fs}
    get_user = by["SQL_INJECTION:shopkart.db:get_user:cur.execute"]
    assert get_user.evidence["taint_path"] == ["app:main", "app:handle", "shopkart.db:get_user"]
    assert get_user.confidence >= 0.85
    count = by["SQL_INJECTION:shopkart.db:count_rows:conn.execute"]
    assert "pass constants" in count.evidence["taint"] and count.confidence < 0.5


def test_security_findings_rank_above_smells():
    _, fs, _ = _findings()
    assert fs[0].category == "security"
    assert fs[0].id == "F001"


def test_tests_are_never_audited():
    _, fs, _ = _findings()
    assert not any(f.file.startswith("tests/") for f in fs)


def test_library_mode_treats_public_names_as_api(tmp_path):
    import shutil
    repo = tmp_path / "lib"
    shutil.copytree(FIXTURE, repo)
    (repo / "pyproject.toml").write_text("[project]\nname='shop'\n")
    cg = CodeGraph.build(str(repo))
    fs, lv = run_rules(cg)
    assert lv.mode == "library"
    assert not any(f.rule == "DEAD_CODE" and f.symbol_id == "shop.pricing:discount" for f in fs)


def test_real_world_patterns(tmp_path):
    """Patterns met on real repos: imported-name sinks, SSTI, password hashing, framework hook methods."""
    from codeaudit.agents.triage import heuristic_triage
    app = tmp_path / "web"
    app.mkdir()
    (app / "app.py").write_text(
        "from hashlib import md5\n"
        "from subprocess import run\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "from flask import Flask, request, render_template_string\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/u')\n"
        "def user():\n"
        "    name = request.args['name']\n"
        "    pwd_hash = md5(request.args['password'].encode()).hexdigest()\n"
        "    run('ls ' + name, shell=True)\n"
        "    return render_template_string('<h1>%s</h1>' % name)\n\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.wfile.write(page())\n\n"
        "def page():\n"
        "    return b'ok'\n\n"
        "if __name__ == '__main__':\n"
        "    HTTPServer(('', 8000), Handler).serve_forever()\n")
    cg = CodeGraph.build(str(app))
    fs, _ = run_rules(cg)
    rules = {f.rule for f in fs}
    assert {"WEAK_HASH", "COMMAND_INJECTION", "TEMPLATE_INJECTION"} <= rules
    assert not any(f.rule == "DEAD_CODE" for f in fs)                        # do_GET is called by http.server
    weak = next(f for f in fs if f.rule == "WEAK_HASH")
    assert heuristic_triage(cg, weak)["verdict"] == "TRUE_POSITIVE"           # hexdigest is not a "digest" cache key
