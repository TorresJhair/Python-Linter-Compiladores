user_id = input("ID: ")
query = "SELECT * FROM users WHERE id = " + user_id 
cursor.execute(query)
