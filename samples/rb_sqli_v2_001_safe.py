import mysql.connector

def authenticate_user(username, password):
    # Input validation using allowlist
    allowed_username_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    if not set(username).issubset(allowed_username_chars):
        raise ValueError("Invalid username")

    allowed_password_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    if not set(password).issubset(allowed_password_chars):
        raise ValueError("Invalid password")

    # Parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    
    if result:
        return True
    else:
        return False