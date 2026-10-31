def discount(user, total, coupon, season, loyalty_years, is_first_order):
    rate = 0
    if user is not None:
        if total > 100:
            if coupon:
                if season == "sale":
                    if loyalty_years > 2:
                        rate = 30
                    else:
                        rate = 20
                else:
                    rate = 10
            elif is_first_order:
                rate = 5
    return rate


def load_rule(text):
    return eval(text)
