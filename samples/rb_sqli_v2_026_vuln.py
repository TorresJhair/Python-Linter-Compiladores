def insert_audit_log(query):
    import os
    return f"{query}?user={os.getlogin()}"