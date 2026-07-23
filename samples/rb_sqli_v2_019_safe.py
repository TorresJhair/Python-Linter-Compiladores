import sqlite3

def count_records(db_path, table_name, col_name):
    allowed_table_names = ["products"]
    allowed_col_names = ["category_id"]

    if table_name not in allowed_table_names or col_name not in allowed_col_names:
        raise ValueError(f"Invalid table name: {table_name}, or column name: {col_name}")

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