"""
Case 11: Enterprise application with complex logic
Safe version demonstrating proper input validation and parameterized queries
"""

import re


ALLOWED_TABLES = {"users", "products", "orders", "inventory"}
ALLOWED_COLUMNS = {
    "users": {"id", "username", "email", "created_at"},
    "products": {"id", "name", "price", "category"},
    "orders": {"id", "user_id", "total", "status"},
    "inventory": {"id", "product_id", "quantity"},
}


def validate_table_name(table: str) -> bool:
    return table.lower() in ALLOWED_TABLES


def validate_columns(table: str, columns: list) -> bool:
    allowed = ALLOWED_COLUMNS.get(table.lower(), set())
    return all(col.lower() in allowed for col in columns)


def sanitize_search_term(term: str) -> str:
    term = term.strip()
    term = re.sub(r"[^\w\s\-]", "", term)
    return term[:100]


user_input = input("Enter search term: ")
safe_value = sanitize_search_term(user_input)

table = input("Enter table: ")
col = input("Enter column: ")

if validate_table_name(table) and validate_columns(table, [col]):
    query = "SELECT ? FROM ? WHERE ? = ?"
    params = (col, table, col, safe_value)


category = input("Enter category: ")
safe_category = sanitize_search_term(category)

if safe_category in ALLOWED_COLUMNS.get("products", set()):
    query2 = "SELECT * FROM products WHERE category = ?"
    params2 = (safe_category,)


new_value = input("Enter new value: ")
condition_value = input("Enter condition value: ")

safe_new = int(new_value)
safe_cond = int(condition_value)
query3 = "UPDATE products SET price = ? WHERE id = ?"
params3 = (safe_new, safe_cond)


class Database:
    def cursor(self):
        return self

    def execute(self, sql, params=None):
        return f"Executed safely: {sql} with {params}"


db = Database()
cursor = db.cursor()
cursor.execute(query, params)
cursor.execute(query2, params2)
cursor.execute(query3, params3)

print("All queries executed safely with parameterized queries")