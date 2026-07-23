def update_user_preferences(user_id, preference_dict):
    set_clause = ', '.join([f'{key} = ?' for key in preference_dict])
    values = list(preference_dict.values())
    query = f"UPDATE users SET {set_clause} WHERE id = ?"
    cursor.execute(query, (*values, user_id))