import sqlite3

def count_records(db_path, table_name, col_name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    group_by_col = f"GROUP BY {col_name}"
    query = f"SELECT {col_name}, COUNT(*) FROM {table_name} {group_by_col};"
    cursor.execute(query)
    result = cursor.fetchall()
    for row in result:
        print(f"{row[0]}: {row[1]} records")
    conn.close()

count_records("my_database.db", "products", "category_id")