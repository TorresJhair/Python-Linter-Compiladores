def update_user_preferences(user_id, prefs):
    placeholders = ', '.join(['?'] * len(prefs))
    set_clause = ', '.join([f"{k} = {v}" for k, v in prefs.items()])
    return f"UPDATE users SET {set_clause} WHERE id = ?"