def build_query(dialect, schema, table, columns, filters, order_by=None, direction="asc", limit=100):
    return ("SELECT * FROM " + table, [])
