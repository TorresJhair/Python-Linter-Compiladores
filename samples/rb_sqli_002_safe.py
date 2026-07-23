def search_products(keyword: str, db):
    result = db.execute(
        'SELECT id, name, price FROM products WHERE name LIKE %s',
        (f'%{keyword}%',)
    )
    return result.fetchall()