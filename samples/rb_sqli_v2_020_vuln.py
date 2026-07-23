def update_user_preferences(user_id, prefs):
    set_clause = ', '.join([f"{k} = ?" for k in prefs.keys()])
    return f"UPDATE users SET {set_clause} WHERE id = ?"