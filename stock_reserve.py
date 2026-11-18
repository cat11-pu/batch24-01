import threading

_LOCK = threading.RLock()


def reserve(stock, qty, reservations=None, max_qty=100):
    return stock - qty
