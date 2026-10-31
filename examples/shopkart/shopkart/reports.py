"""Reports and pricing formulas."""
from . import inventory


def monthly_report(orders, month, year, currency, fmt, include_tax):
    lines = []
    rate = default_tax_rate()
    for o in orders:
        if o.get("month", month) == month:
            if o.get("year", year) == year:
                if fmt == "csv":
                    if include_tax:
                        lines.append(f"{o['customer']},{o['total'] * (1 + rate):.2f},{currency}")
                    else:
                        lines.append(f"{o['customer']},{o['total']:.2f},{currency}")
                elif fmt == "text":
                    if include_tax:
                        lines.append(f"{o['customer']}: {currency} {o['total'] * (1 + rate):.2f}")
                    else:
                        lines.append(f"{o['customer']}: {currency} {o['total']:.2f}")
    return lines


def default_tax_rate():
    return eval("0.18")


def evaluate_formula(expr):
    return eval(expr)


def low_stock_alert(inv):
    items = inventory.low_stock(inv)
    return "low stock: " + ", ".join(items) if items else "stock ok"
