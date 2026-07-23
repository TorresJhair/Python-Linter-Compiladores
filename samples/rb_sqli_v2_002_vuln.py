from fastapi import FastAPI

app = FastAPI()

@app.get("/search")
def search_blog_posts(tag: str):
    query = f"SELECT * FROM blog_posts WHERE tags LIKE '%{tag}%'"
    # Execute SQL query to fetch results from database and return them
    return query