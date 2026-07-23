def update_preferences(user_id, preference_dict):
    set_clause = ", ".join([f"{key} = '{value}'" for key, value in preference_dict.items()])
    query = f"UPDATE users SET {set_clause} WHERE id = {user_id}"
    return query

# Example usage:
update_query = update_preferences(1, {"name": "John", "age": 30})
print(update_query)