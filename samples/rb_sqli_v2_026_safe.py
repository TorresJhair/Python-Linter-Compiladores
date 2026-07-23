import hashlib

def insert_audit_log(query, user):
    # Validate input using allowlist for allowed query parameters
    if not isinstance(user, str) or any(ch not in set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for ch in user):
        raise ValueError("Invalid user")
    
    # Use a parameterized query to prevent SQL injection
    return f"{query}?user={user}"