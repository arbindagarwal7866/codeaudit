"""Old pricing code from version 1 (nothing imports this any more)."""


def old_discount(total, years):
    if years > 5:
        return total * 0.8
    return total * 0.95
