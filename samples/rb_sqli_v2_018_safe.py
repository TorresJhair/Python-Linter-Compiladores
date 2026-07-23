import psycopg2

def get_paginated_results(page, size, db_params):
    if not isinstance(page, int) or not isinstance(size, int):
        raise ValueError("Both page and size must be integers.")
        
    if page < 1:
        raise ValueError("Page number should be greater than zero.")
    
    offset = (page - 1) * size
    limit_query = f"LIMIT {size} OFFSET {offset}"
    
    with psycopg2.connect(**db_params) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM your_table_name " + limit_query)
            results = cur.fetchall()
            return results