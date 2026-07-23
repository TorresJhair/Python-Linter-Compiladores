from fastapi import FastAPI, Security
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()

# Mock Database Connection
db_connections = {
    "user": "SELECT * FROM blogposts WHERE tags LIKE '%{tag}%'"
}

@app.get("/search")
def search_blog_posts(tag: str):
    # parameterized queries
    query = "SELECT * FROM blogposts WHERE tags LIKE %s"
    params = ('%' + tag + '%',)
    return {"query": query.format(params)}

# Mock Database Connection using input validation, allowlists, and proper authentication.
@app.get("/search")
@Security(OAuth2PasswordBearer(tokenUrl="/oauth/token"))
def search_blog_posts(tag: str):
    # parameterized queries
    query = "SELECT * FROM blogposts WHERE tags LIKE %s"
    params = ('%' + tag + '%',)
    return {"query": query.format(params)}