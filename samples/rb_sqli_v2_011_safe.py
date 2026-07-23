import mysql.connector

def authenticate(username, password):
    # Input validation
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Invalid input type")
    
    # Allowlist check (ensure username is in the allowlist)
    ALLOWED_USERNAME = ["admin", "user"]
    if username not in ALLOWED_USERNAME:
        raise ValueError("Username not allowed")

    # Parameterized query
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    
    try:
        conn = mysql.connector.connect(
            host='your_host',
            database='your_database'
        )
        
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        result = cursor.fetchone()

        # Proper authentication
        if result and result[0] == 'hashed_password':
            return True
    finally:
        conn.close()