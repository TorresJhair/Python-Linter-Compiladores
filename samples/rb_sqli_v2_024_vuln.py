def filter_products_by_price_range(session, min_price, max_price):
    return session.query(Product).filter("price BETWEEN ? AND ?", f"{min_price}", f"{max_price}")