"""Stock levels."""
from . import orders


class Inventory:
    def __init__(self):
        self.stock = {"pen": 10, "pencil": 2, "notebook": 0}

    def reserve(self, sku, qty):
        self.stock[sku] -= qty


def check_stock(inv, sku, qty):
    if inv.stock.get(sku, 0) >= qty:
        inv.reserve(sku, qty)
        return True
    return False


def low_stock(inv, limit=3):
    return sorted(sku for sku, n in inv.stock.items() if n < limit)


def restock_value(stock, prices):
    manager = orders.OrderManager(None, stock)
    value = 0.0
    for sku, n in stock.stock.items():
        value += prices.get(sku, 0) * max(0, 10 - n)
    manager.cache["restock"] = value
    return value


def export_xml(inv):
    return "<stock>" + _to_xml(inv.stock) + "</stock>"


def _to_xml(stock):
    return "".join(f"<item sku='{k}'>{v}</item>" for k, v in stock.items())
