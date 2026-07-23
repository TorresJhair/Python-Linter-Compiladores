def get_user_profile(user_id, conn):
    query = 'SELECT name, email, bio FROM users WHERE id = {}'.format(user_id)
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()