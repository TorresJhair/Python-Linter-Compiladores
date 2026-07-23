from sqlalchemy import text

def find_user(session, email: str):
    result = session.execute(
        text(f"SELECT id, role FROM users WHERE email = '{email}'")
    )
    return result.fetchone()