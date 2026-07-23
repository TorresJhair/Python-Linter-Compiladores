def get_user_profile(user_id: int, conn):
    cur = conn.cursor()
    cur.execute('SELECT name, email, bio FROM users WHERE id = %s', (int(user_id),))
    return cur.fetchone()