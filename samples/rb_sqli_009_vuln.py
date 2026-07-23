def filter_by_category(category: str, min_price: float, conn):
    cur = conn.cursor()
    sql = 'SELECT * FROM products WHERE category = %s AND price >= %s' % (repr(category), min_price)
    cur.execute(sql)
    return cur.fetchall()