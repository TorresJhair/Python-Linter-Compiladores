"""
CVE: CVE-2025-59681
Description: Django SQL injection in column aliases via QuerySet.annotate(), alias(),
             aggregate(), extra() on MySQL/MariaDB
Source: https://nvd.nist.gov/vuln/detail/CVE-2025-59681
Pattern: Column alias names passed as dictionary keys to annotate()/alias()/aggregate()/extra()
         were not sanitized on MySQL/MariaDB, allowing SQL injection through crafted
         dictionary keys used as SELECT column aliases.
"""

import sqlite3


def vulnerable_column_alias_injection():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("CREATE TABLE products (id INTEGER, name TEXT, price REAL)")
    cur.execute(
        "INSERT INTO products VALUES "
        "(1, 'Widget', 9.99), "
        "(2, 'Gadget', 19.99), "
        "(3, 'Doohickey', 29.99)"
    )

    user_alias = "discounted_price') AS injected_alias FROM products UNION SELECT 'x', 'y', 99.99--"

    query = (
        f"SELECT id, name, price AS \"{user_alias}\" FROM products"
    )
    cur.execute(query)
    print("[VULNERABLE CVE-2025-59681] Column alias injection:")
    for row in cur.fetchall():
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    vulnerable_column_alias_injection()