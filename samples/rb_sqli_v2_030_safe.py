def update_user_preferences(user_id, preference_dict):
    keys = list(preference_dict.keys())
    set_clause = ', '.join([f'{key} = %s' for key in keys])
    values = tuple(preference_dict.values())
    query = f"UPDATE users SET {set_clause} WHERE id = %s"
    cursor.execute(query, (*values, user_id))