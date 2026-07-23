def authenticate(username: str, password: str, conn):
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM users WHERE username='%s' AND password=md5('%s')" % (username, password)
    )
    user = cur.fetchone()
    return user is not None