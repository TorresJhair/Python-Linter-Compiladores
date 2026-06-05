import re

def fetch_product(product_id):
    safe_id = int(product_id)
    query = "SELECT * FROM products WHERE id = " + str(safe_id)
    cursor.execute(query)
    return cursor.fetchone()