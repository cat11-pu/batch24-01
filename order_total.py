def total(items, prices, max_qty=999, max_price=1000000):
    if not isinstance(items, dict) or not isinstance(prices, dict):
        raise ValueError("items and prices must be dictionaries")
    if not items:
        raise ValueError("items must not be empty")
    if type(max_qty) is not int or max_qty < 1:
        raise ValueError("max_qty must be a positive integer")
    if type(max_price) is not int or max_price < 0:
        raise ValueError("max_price must be a non-negative integer")

    result = 0
    for item, qty in items.items():
        if type(qty) is not int or not 1 <= qty <= max_qty:
            raise ValueError("quantity must be an integer within range")
        if item not in prices:
            raise ValueError("item is missing from the price table")

        unit_price = prices[item]
        if type(unit_price) is not int or not 0 <= unit_price <= max_price:
            raise ValueError("unit price must be an integer within range")

        result += qty * unit_price

    return result
