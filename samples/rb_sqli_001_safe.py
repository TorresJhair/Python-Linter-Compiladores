def get_user_by_name(username: str, conn):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    return cursor.fetchone()