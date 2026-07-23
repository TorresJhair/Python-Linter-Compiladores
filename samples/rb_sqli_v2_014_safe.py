import paramiko
from sqlalchemy import text

def get_products_in_price_range(session, min_price, max_price):
    try:
        validated_min_price = float(min_price)
        validated_max_price = float(max_price)

        if not (isinstance(validated_min_price, (int, float)) and isinstance(validated_max_price, (int, float))):
            raise ValueError("Invalid input type for price range")

        query = text(f"price between :min_price and :max_price")
        result = session.execute(query, {"min_price": validated_min_price, "max_price": validated_max_price})
        
        return result.fetchall()
    except Exception as e:
        # Handle exception properly
        raise e