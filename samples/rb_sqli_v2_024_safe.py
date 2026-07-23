def filter_products_by_price_range(session, min_price, max_price):
    return session.query(Product).filter(Product.price.between(min_price, max_price))