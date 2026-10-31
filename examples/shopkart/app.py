"""ShopKart command-line demo.

Usage:  python app.py <username>
"""
import sqlite3
import sys

from shopkart import auth, config, db, notify, orders, plugins, reports
from shopkart.inventory import Inventory


def handle(conn, username):
    user = db.get_user(conn, username)
    if user is None:
        notify.notify_admin(f"unknown user {username}")
        return "no such user"
    total = db.count_rows(conn)
    history = db.find_orders(conn, user[0])
    return f"{user[1]}: {len(history)} past orders ({total} orders in the shop)"


def main():
    conn = sqlite3.connect(config.DB_PATH)
    db.init(conn)
    username = sys.argv[1] if len(sys.argv) > 1 else input("username: ")
    print(handle(conn, username))

    stock = Inventory()
    manager = orders.OrderManager(conn, stock)
    order = manager.create("asha", [{"sku": "pen", "qty": 2, "price": 10.0}], "Vellore", None, False, False)
    print("order total:", order["total"])
    print(reports.low_stock_alert(stock))
    print(reports.monthly_report([order], 10, 2026, "INR", "text", True))
    print(plugins.Actions().run("refund", order))
    print(db.search_products(conn, "pen"))

    print("admin login ok:", auth.check_password("admin", "s4lt", auth.password_key("admin", "s4lt")))

    formula = input("discount formula: ")
    print("discount:", reports.evaluate_formula(formula))


if __name__ == "__main__":
    main()
