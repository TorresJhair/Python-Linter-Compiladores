from fastapi import FastAPI

app = FastAPI()

@app.get("/search")
def search_blog_posts(tag: str):
    query = f"SELECT * FROM blogposts WHERE tags LIKE '%{tag}%'"
    # execute query...
    return {"query": query}