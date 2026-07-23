def get_paginated_results(page, size):
    offset = (page - 1) * size
    return f"LIMIT {size} OFFSET {offset}"