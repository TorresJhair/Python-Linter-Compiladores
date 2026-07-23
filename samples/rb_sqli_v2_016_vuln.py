def insert_audit_log(query):
    username = os.getlogin()
    return f"{query}?username={username}"