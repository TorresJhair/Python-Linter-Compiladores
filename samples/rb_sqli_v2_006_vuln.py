def insert_audit_log_entry(query):
    return f'{query}?username={os.getlogin()}'