from .utils import fmt_price


class Base:
    def log(self, msg):
        print(msg)


class Cart(Base):
    def __init__(self):
        self.items = []

    def add(self, item, qty=1):
        if qty <= 0 or item is None:
            raise ValueError("bad")
        self.items.append((item, qty))
        self.log("added")

    def total(self):
        t = 0
        for item, qty in self.items:
            t += item.price * qty
        return fmt_price(t)
