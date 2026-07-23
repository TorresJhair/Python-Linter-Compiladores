def get_orders_for_status(status: str, conn):
    cursor = conn.cursor()
    cursor.execute('SELECT order_id, total FROM orders WHERE status = ?', (status,))
    return cursor.fetchall()