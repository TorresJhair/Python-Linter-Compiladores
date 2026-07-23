import mysql.connector
from werkzeug.security import check_password_hash

def authenticate_user(username, password):
    conn = mysql.connector.connect(
        host="your_host",
        user="your_user",
        password="your_password",
        database="your_database"
    )
    cursor = conn.cursor()
    query = "SELECT password FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    if result:
        is_valid = check_password_hash(result[0], password)
        return is_valid
    else:
        return False

# Example usage:
print(authenticate_user("example_username", "example_password"))