"""
Case 8: Safe ORM queries using parameterized statements
This is the SECURE version with proper query construction
"""

from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

DATABASE_URI = "postgresql://user:pass@localhost/mydb"
engine = create_engine(DATABASE_URI)


@app.route("/user/profile")
def get_user_profile():
    username = request.args.get("username", "")
    limit = int(request.args.get("limit", "10"))

    query = text("SELECT * FROM users WHERE username = :username LIMIT :limit")

    with engine.connect() as conn:
        result = conn.execute(query, {"username": username, "limit": limit})
        users = [{"id": row[0], "username": row[1], "email": row[2]} for row in result]

    return jsonify(users)


@app.route("/admin/search")
def admin_search():
    search_term = request.form.get("q", "")
    category = request.form.get("category", "all")

    if category == "all":
        query = text("SELECT id, name, description FROM products WHERE name LIKE :search")
        params = {"search": f"%{search_term}%"}
    else:
        query = text("SELECT id, name, description FROM products WHERE name LIKE :search AND category = :cat")
        params = {"search": f"%{search_term}%", "cat": category}

    with engine.connect() as conn:
        result = conn.execute(query, params)
        products = [{"id": row[0], "name": row[1]} for row in result]

    return jsonify(products)


@app.route("/product/<int:product_id>")
def get_product(product_id):
    safe_id = int(product_id)

    query = text("SELECT * FROM products WHERE id = :id")

    with engine.connect() as conn:
        result = conn.execute(query, {"id": safe_id})
        product = result.fetchone()

    if product:
        return jsonify({"id": product[0], "name": product[1], "price": product[3]})
    return jsonify({"error": "Product not found"}), 404


@app.route("/order/create", methods=["POST"])
def create_order():
    data = request.get_json()
    user_id = int(data.get("user_id", 0))
    product_ids = data.get("product_ids", [])

    validated_ids = [int(pid) for pid in product_ids]

    query = text("INSERT INTO orders (user_id, product_ids) VALUES (:uid, :pids) RETURNING id")

    with engine.connect() as conn:
        result = conn.execute(query, {"uid": user_id, "pids": validated_ids})
        order_id = result.fetchone()[0]

    return jsonify({"order_id": order_id})


if __name__ == "__main__":
    app.run(debug=True)