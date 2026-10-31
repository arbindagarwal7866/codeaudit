import pickle
import sqlite3

import pytest

from shopkart import auth, db, orders, plugins, reports
from shopkart.inventory import Inventory, check_stock, low_stock


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    db.init(c)
    return c


def test_get_user(conn):
    assert db.get_user(conn, "asha") == (1, "asha")
    assert db.get_user(conn, "nobody") is None


def test_find_orders(conn):
    assert sorted(t for _, t in db.find_orders(conn, 1)) == [99.5, 250.0]


def test_count_rows(conn):
    assert db.count_rows(conn) == 3


def test_search_products(conn):
    assert db.search_products(conn, "pen") == [("pen",), ("pencil",)]


def test_create_order_totals(conn):
    m = orders.OrderManager(conn, Inventory())
    items = [{"sku": "pen", "qty": 2, "price": 10.0}, {"sku": "pencil", "qty": 5, "price": 1.0},
             {"sku": "pen", "qty": 0, "price": 3.0}, {"sku": "pen", "qty": 1, "price": None}]
    assert m.create("asha", items, "x", None, False, False)["total"] == 20.0
    assert m.create("ravi", [{"sku": "pen", "qty": 1, "price": 10.0}], "x", "VIP10", True, True)["total"] == 157.0
    with pytest.raises(ValueError):
        m.create("asha", [], "x", None, False, False)


def test_cache_key_is_stable(conn):
    m = orders.OrderManager(conn, Inventory())
    assert m.cache_key(7) == m.cache_key(7) and len(m.cache_key(7)) >= 32


def test_restore_session_roundtrip(conn):
    m = orders.OrderManager(conn, Inventory())
    assert m.restore_session(pickle.dumps({"a": 1})) == {"a": 1}


def test_stock():
    inv = Inventory()
    assert check_stock(inv, "pen", 3) and inv.stock["pen"] == 7
    assert not check_stock(inv, "notebook", 1)
    assert low_stock(inv) == ["notebook", "pencil"]


def test_reports():
    o = {"customer": "asha", "total": 100.0}
    assert reports.monthly_report([o], 1, 2026, "INR", "text", True) == ["asha: INR 118.00"]
    assert reports.monthly_report([o], 1, 2026, "INR", "csv", False) == ["asha,100.00,INR"]
    assert reports.monthly_report([o], 1, 2026, "INR", "pdf", False) == []
    assert reports.evaluate_formula("0.15") == 0.15
    assert reports.default_tax_rate() == 0.18


def test_dynamic_action():
    assert plugins.Actions().run("refund", {"total": 5}) == {"refunded": 5}


def test_password_roundtrip():
    stored = auth.password_key("hunter2", "salt")
    assert auth.check_password("hunter2", "salt", stored)
    assert not auth.check_password("wrong", "salt", stored)
