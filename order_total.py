def total(items, prices, max_qty=999, max_price=1000000):
    return sum(qty * prices[item] for item, qty in items.items())
