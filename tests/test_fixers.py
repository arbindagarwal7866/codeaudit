"""Every deterministic fix must pass the full Validator, including the demo project's own tests."""
import sys

import pytest

from codeaudit.agents.fixers import deterministic_fix
from codeaudit.agents.validator import Change, validate, replace_symbol
from codeaudit.graph import CodeGraph
from codeaudit.rules import run_rules

TESTS = [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"]


def _setup(repo):
    cg = CodeGraph.build(str(repo))
    fs, lv = run_rules(cg)
    return cg, {f.key: f for f in fs}, {f.key for f in fs}


@pytest.mark.parametrize("key,expect", [
    ("SQL_INJECTION:shopkart.db:get_user:cur.execute", "WHERE name = ?', (username,))"),
    ("SQL_INJECTION:shopkart.db:find_orders:conn.execute", "conn.execute(query, (customer_id,))"),
    ("CODE_INJECTION:shopkart.reports:evaluate_formula:eval", "ast.literal_eval(expr)"),
    ("COMMAND_INJECTION:shopkart.orders:OrderManager.export:subprocess.run", "['tar', 'czf', str(filename), 'data/']"),
    ("HARDCODED_SECRET:shopkart.config::SECRET_KEY", 'os.environ.get("SECRET_KEY", "")'),
    ("WEAK_HASH:shopkart.auth:password_key:hashlib.sha1", "hashlib.sha256("),
    ("DEEP_NESTING:shopkart.orders:OrderManager.create", "continue"),
    ("DEEP_NESTING:shopkart.reports:monthly_report", "continue"),
    ("DEAD_CODE:shopkart.inventory:export_xml", ""),
    ("CYCLIC_DEPENDENCY:shopkart.inventory|shopkart.orders", ""),
])
def test_fix_is_validated(shopkart, key, expect):
    cg, by, keys = _setup(shopkart)
    ch = deterministic_fix(cg, by[key])
    assert ch is not None
    res = validate(cg, by[key], ch, keys, test_cmd=TESTS)
    assert res["ok"], res["checks"]
    assert expect in "".join(ch.files.values())
    names = [c["name"] for c in res["checks"]]
    assert {"syntax", "compiles", "finding resolved", "no new issues", "tests pass"} <= set(names)


def test_cycle_fix_removes_import(shopkart):
    cg, by, keys = _setup(shopkart)
    ch = deterministic_fix(cg, by["CYCLIC_DEPENDENCY:shopkart.inventory|shopkart.orders"])
    text = ch.files["shopkart/inventory.py"]
    assert "from . import orders" not in text and "def restock_value" not in text


def test_unsafe_patterns_are_left_alone(shopkart):
    cg, by, _ = _setup(shopkart)
    assert deterministic_fix(cg, by["COMMAND_INJECTION:shopkart.notify:notify_admin:os.system"]) is None   # '>>' redirect
    assert deterministic_fix(cg, by["DEAD_CODE:shopkart.plugins:Actions.handle_refund"]) is None         # dynamic
    assert deterministic_fix(cg, by["INSECURE_DESERIALIZATION:shopkart.orders:OrderManager.restore_session:pickle.loads"]) is None


def test_validator_rejects_signature_change_and_breaking_tests(shopkart):
    cg, by, keys = _setup(shopkart)
    f = by["SQL_INJECTION:shopkart.db:get_user:cur.execute"]
    bad = Change({f.file: replace_symbol(cg, f.symbol_id, "def get_user(conn):\n    return None\n")}, "x", "test")
    res = validate(cg, f, bad, keys)
    assert not res["ok"] and any(c["name"] == "signature" and not c["passed"] for c in res["checks"])
    wrong = Change({f.file: replace_symbol(cg, f.symbol_id,
                                          "def get_user(conn, username):\n    return None\n")}, "x", "test")
    res = validate(cg, f, wrong, keys, test_cmd=TESTS)
    assert not res["ok"] and any(c["name"] == "tests pass" and not c["passed"] for c in res["checks"])


def test_validator_rejects_new_issues(shopkart):
    cg, by, keys = _setup(shopkart)
    f = by["SQL_INJECTION:shopkart.db:get_user:cur.execute"]
    sneaky = ("def get_user(conn, username):\n    cur = conn.cursor()\n"
              "    cur.execute('SELECT id, name FROM users WHERE name = ?', (username,))\n"
              "    eval(username)\n    return cur.fetchone()\n")
    res = validate(cg, f, Change({f.file: replace_symbol(cg, f.symbol_id, sneaky)}, "x", "test"), keys)
    assert not res["ok"] and any(c["name"] == "no new issues" and not c["passed"] for c in res["checks"])
