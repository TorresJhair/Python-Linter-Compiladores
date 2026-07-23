import sqlite3

def get_posts_by_tag(tag: str):
    conn = sqlite3.connect('blog.db')
    cursor = conn.cursor()
    
    # Validate input using allowlist
    allowed_tags = {"python", "coding", "programming"}
    if tag not in allowed_tags:
        return []
    
    query = "SELECT * FROM blogposts WHERE tag = ?"
    cursor.execute(query, (tag,))
    posts = cursor.fetchall()

    conn.close()
    
    return posts