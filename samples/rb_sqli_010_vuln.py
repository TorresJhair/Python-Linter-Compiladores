from flask import request
import sqlite3

@app.route('/admin/users')
def admin_users():
    sort_col = request.args.get('sort', 'id')
    order = request.args.get('order', 'ASC')
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    # Sort column and order direction are not parameterisable in SQL
    cur.execute(f'SELECT id, username, email FROM users ORDER BY {sort_col} {order}')
    return jsonify(cur.fetchall())