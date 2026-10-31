"""Order actions, dispatched by name."""


class Actions:
    def run(self, action, order):
        handler = getattr(self, f"handle_{action}")
        return handler(order)

    def handle_refund(self, order):
        return {"refunded": order["total"]}
