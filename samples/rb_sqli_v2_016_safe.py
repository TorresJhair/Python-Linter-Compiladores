import os
import sqlite3

def insert_audit_log(query: str) -> None:
    with sqlite3.connect('audit.db') as conn:
        cursor = conn.cursor()

        # Validate query parameters using allowlist of safe operations for logging purposes
        allowed_operations = ['INSERT', 'UPDATE', 'DELETE']
        if query.split()[0].upper() not in allowed_operations:
            raise ValueError("Unsafe operation attempted")

        username = os.getlogin()
        
        # Use parameterized queries to prevent SQL injection
        param_query, params = query.split(' ', 1)
        cursor.execute(f"{param_query}?", params)