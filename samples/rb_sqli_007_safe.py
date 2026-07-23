import hashlib

def authenticate(username: str, password: str, conn):
    password_hash = hashlib.md5(password.encode()).hexdigest()
    cur = conn.cursor()
    cur.execute(
        'SELECT id FROM users WHERE username = %s AND password = %s',
        (username, password_hash)
    )
    return cur.fetchone() is not None