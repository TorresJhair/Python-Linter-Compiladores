def update_preferences(user_id, preference_dict):
    set_clauses = []
    placeholders = []
    for key, value in preference_dict.items():
        placeholders.append(f"{key} = ?")
        set_clauses.append(key)
    placeholder_clause = ", ".join(placeholders)
    
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
    values = tuple([value for _, value in preference_dict.items()] + [user_id])
    
    return (query, values)

# Example usage:
update_query, update_values = update_preferences(1, {"name": "John", "age": 30})
print(update_query)
print(update_values)