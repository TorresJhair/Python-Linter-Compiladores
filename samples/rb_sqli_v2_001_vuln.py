import mysql.connector

def authenticate_user(username, password):
    conn = mysql.connector.connect(
        host="your_host",
        user="root",
        password="password"
    )
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    if result:
        return True
    else:
        return False