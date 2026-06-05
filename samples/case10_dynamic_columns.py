"""
Case 10: Dynamic table and column names with SQL injection
Demonstrates injection through dynamically built column/table names
"""

table_name = input("Enter table name: ")
column_name = input("Enter column name: ")
value = input("Enter value: ")

sql = "SELECT " + column_name + " FROM " + table_name + " WHERE " + column_name + " = '" + value + "'"


category = input("Enter category: ")
min_price = input("Enter min price: ")
order_col = input("Enter order column: ")

base_sql = "SELECT * FROM products WHERE 1=1"
base_sql += " AND category = '" + category + "'"
base_sql += " AND price >= " + min_price
base_sql += " ORDER BY " + order_col


class Database:
    def cursor(self):
        return self

    def execute(self, sql):
        return f"Executed: {sql}"


db = Database()
cursor = db.cursor()
cursor.execute(sql)
cursor.execute(base_sql)

print("Queries executed")