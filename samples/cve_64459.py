"""
CVE: CVE-2025-64459
Description: Django Q() objects / QuerySet SQL injection via _connector keyword argument
Source: https://nvd.nist.gov/vuln/detail/CVE-2025-64459
Pattern: The _connector keyword argument in QuerySet.filter(), exclude(), get(), and Q()
         objects was subject to SQL injection when using a suitably crafted dictionary with
         dictionary expansion. An attacker can inject SQL fragments through _connector
         to manipulate WHERE clause structure.
"""

import sqlite3


def vulnerable_q_connector_injection():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute(
        "CREATE TABLE users (id INTEGER, username TEXT, password TEXT, is_superuser INTEGER)"
    )
    cur.execute(
        "INSERT INTO users VALUES "
        "(1, 'alice', 'secret1', 0), "
        "(2, 'bob', 'secret2', 0), "
        "(3, 'admin', 'adminpass', 1)"
    )

    user_input = {"username": "nonexistent", "_connector": ") OR 1=1--"}

    conditions = []
    params = []
    for key, value in user_input.items():
        if key == "_connector":
            continue
        conditions.append(f"{key}=?")
        params.append(value)

    connector = user_input.get("_connector", "AND")
    where_clause = f" {connector} ".join(conditions)

    query = f"SELECT * FROM users WHERE ({where_clause})"
    cur.execute(query, params)
    print("[VULNERABLE CVE-2025-64459] Q() _connector injection:")
    for row in cur.fetchall():
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    vulnerable_q_connector_injection()