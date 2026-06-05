"""
Case 7: ORM Query with raw SQL injection
Realistic scenario using SQLAlchemy with raw SQL
"""

username = input("Enter username: ")
limit = input("Enter limit: ")

query = f"SELECT * FROM users WHERE username = '{username}' LIMIT {limit}"

class Database:
    def cursor(self):
        return self

    def execute(self, sql):
        return f"Executed: {sql}"


db = Database()
cursor = db.cursor()
result = cursor.execute(query)

print("Query executed:", result)