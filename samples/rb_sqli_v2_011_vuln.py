import mysql.connector

def authenticate(username, password):
    conn = mysql.connector.connect(
        host='your_host',
        database='your_database',
        user='root',
        password='your_password'
    )
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    return bool(result)