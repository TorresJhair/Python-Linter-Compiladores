def filter_by_category(category: str, min_price: float, conn):
    cur = conn.cursor()
    cur.execute(
        'SELECT * FROM products WHERE category = %s AND price >= %s',
        (category, min_price)
    )
    return cur.fetchall()