def get_paginated_results(query, page, size):
    offset = (page - 1) * size
    return f"{query} LIMIT {size} OFFSET {offset}"