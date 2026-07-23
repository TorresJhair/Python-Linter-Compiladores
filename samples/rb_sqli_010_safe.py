@app.route('/admin/users')
def admin_users():
    ALLOWED_COLS = {'id', 'username', 'email', 'created_at'}
    ALLOWED_ORDERS = {'ASC', 'DESC'}
    sort_col = request.args.get('sort', 'id')
    order = request.args.get('order', 'ASC').upper()
    if sort_col not in ALLOWED_COLS or order not in ALLOWED_ORDERS:
        abort(400)
    conn = sqlite3.connect('app.db')
    cur = conn.cursor()
    cur.execute(f'SELECT id, username, email FROM users ORDER BY {sort_col} {order}')
    return jsonify(cur.fetchall())