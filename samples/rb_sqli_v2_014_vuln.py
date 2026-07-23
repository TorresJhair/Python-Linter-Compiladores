def get_products_in_price_range(session, min_price, max_price):
    return session.query(Product).filter(
        f"price between {min_price} and {max_price}"
    ).all()