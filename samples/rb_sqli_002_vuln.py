def search_products(keyword: str, db):
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
    result = db.execute(query)
    return result.fetchall()