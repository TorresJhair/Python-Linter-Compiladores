import sqlalchemy

def get_paginated_results(query, page, size, metadata):
    # Validate page and size inputs
    if not isinstance(page, int) or not isinstance(size, int) or page < 1:
        raise ValueError("Invalid 'page' parameter")
    
    if size <= 0:
        raise ValueError("Invalid 'size' parameter")

    # Use SQLAlchemy's text construct for a safe query execution
    from sqlalchemy import text

    offset = (page - 1) * size
    
    return text(f"{query} LIMIT :size OFFSET :offset", bindparams=[('size', size), ('offset', offset)])

# Example usage:
# Assuming you have an SQLAlchemy engine and session setup, use it like so:
# query = get_paginated_results("SELECT * FROM some_table", 1, 10, metadata)