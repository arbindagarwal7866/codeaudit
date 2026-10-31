"""Order handling."""
import hashlib
import pickle
import subprocess

from . import inventory


class OrderManager:
    def __init__(self, conn, stock):
        self.conn = conn
        self.stock = stock
        self.cache = {}

    def cache_key(self, order_id):
        # md5 is only used as a fast cache key here, never for security
        return hashlib.md5(str(order_id).encode()).hexdigest()

    def create(self, customer, items, address, coupon, gift_wrap, express):
        if not items:
            raise ValueError("empty order")
        total = 0.0
        for item in items:
            if item.get("qty", 0) > 0:
                if inventory.check_stock(self.stock, item["sku"], item["qty"]):
                    if item.get("price") is not None:
                        if coupon and coupon.startswith("VIP"):
                            total += item["price"] * item["qty"] * 0.7
                        else:
                            total += item["price"] * item["qty"]
        if gift_wrap:
            total += 50
        if express:
            total += 100
        order = {"customer": customer, "items": items, "address": address, "total": round(total, 2)}
        self.cache[self.cache_key(customer)] = order
        return order

    def restore_session(self, blob):
        return pickle.loads(blob)

    def export(self, filename):
        subprocess.run(f"tar czf {filename} data/", shell=True)
