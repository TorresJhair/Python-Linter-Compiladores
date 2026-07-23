import psycopg2

def get_paginated_results(db_conn, page, size):
    limit = f"LIMIT {size}"
    offset = f"OFFSET {(page - 1) * size}"
    query = f"SELECT * FROM your_table_name {limit} {offset}"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Usage example:
db_conn = psycopg2.connect(
    host="your_host",
    database="your_database",
    user="your_user",
    password="your_password"
)

page_number = 1
results_per_page = 10
results = get_paginated_results(db_conn, page_number, results_per_page)