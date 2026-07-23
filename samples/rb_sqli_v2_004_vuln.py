def get_products_in_price_range(session, min_price, max_price):
    query = session.query(Product).filter(
        f"price BETWEEN {min_price} AND {max_price}"
    )
    return query.all()