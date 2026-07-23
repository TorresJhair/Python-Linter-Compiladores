from sqlalchemy import between

def get_products_in_price_range(session, min_price, max_price):
    query = session.query(Product).filter(between(Product.price, min_price, max_price))
    return query.all()