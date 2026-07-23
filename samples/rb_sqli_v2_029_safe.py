import sqlite3

def count_records_per_category(db_path, table_name, col_name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    group_by_clause = f"GROUP BY {col_name}"
    query = f"SELECT {col_name}, COUNT(*) AS record_count FROM {table_name} {group_by_clause};"
    
    # Input validation
    if not isinstance(col_name, str) or not col_name:
        raise ValueError("Column name must be a non-empty string.")
    
    cursor.execute(query)
    results = cursor.fetchall()
    return [(row[0], row[1]) for row in results]

# Example usage:
db_path = "example.db"
table_name = "products"
col_name = "category"

records_per_category = count_records_per_category(db_path, table_name, col_name)
for category, count in records_per_category:
    print(f"{category}: {count}")