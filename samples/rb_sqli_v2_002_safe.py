from fastapi import FastAPI, Security
from sqlalchemy.orm import Session
from sqlalchemy.sql import selectinorder

app = FastAPI()

# Define a security function for parameterized queries
def authenticate_query(tag: str):
    tag = tag.strip()
    
    # Parameterized query using SQLAlchemy to avoid SQL injection.
    query = selectinorder(
        select(blog_posts).where(
            blog_posts.c.tags.like(f"%{tag}%")
        )
    )

    return query

@app.get("/search")
def search_blog_posts(tag: str, db: Session = Security(authenticate_query)):
    # Execute the SQL query to fetch results from the database and return them
    result = db.execute(query)
    posts = [dict(row) for row in result]
    return posts