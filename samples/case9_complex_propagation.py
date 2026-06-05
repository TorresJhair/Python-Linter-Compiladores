"""
Case 9: Complex taint propagation through multiple operations
Demonstrates how taint flows through various Python constructs
"""

user_input = input("Enter search: ")

filtered = user_input.replace("'", "")
filtered = filtered.replace(";", "")

keywords = filtered.split()
for i, kw in enumerate(keywords):
    keywords[i] = kw.strip()

search_terms = " OR ".join([f"title LIKE '%{kw}%'" for kw in keywords])
final_query = "SELECT * FROM posts WHERE " + search_terms

username = input("Enter username: ")
email = input("Enter email: ")
bio = input("Enter bio: ")

clean_username = username.replace("'", "''")
query = "INSERT INTO profiles (username, email, bio) VALUES ('" + clean_username + "', '" + email + "', '" + bio + "')"


class Database:
    def cursor(self):
        return self

    def execute(self, sql):
        return f"Executed: {sql}"


db = Database()
cursor = db.cursor()

cursor.execute(final_query)
cursor.execute(query)

print("Queries executed")