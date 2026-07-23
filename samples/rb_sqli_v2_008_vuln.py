def get_paginated_results(page, size):
    limit = f"LIMIT {size}"
    offset = f"OFFSET {(page - 1) * size}"
    query = f"SELECT * FROM your_table_name {limit} {offset}"
    return query