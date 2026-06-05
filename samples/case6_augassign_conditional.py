base_query = "SELECT * FROM logs WHERE 1=1"
if user_filter:
    base_query += " AND user = '" + user_input + "'"
db.execute(base_query)
