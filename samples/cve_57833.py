"""
CVE: CVE-2025-57833
Description: Django FilteredRelation SQL injection in column aliases via dictionary expansion
Source: https://nvd.nist.gov/vuln/detail/CVE-2025-57833
Pattern: FilteredRelation aliases passed as **kwargs to annotate()/alias() were not properly
         quoted, allowing SQL injection through crafted dictionary keys used as column aliases.
         The vulnerability occurs because alias names in FilteredRelation bypass Django's
         usual quoting logic (quote_name_unless_alias) - they are mistakenly flagged as
         pre-resolved, so no quoting is applied.
"""

import sqlite3


def vulnerable_filteredrelation_alias_injection():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("CREATE TABLE orders (id INTEGER, customer TEXT, amount REAL)")
    cur.execute("CREATE TABLE payments (id INTEGER, order_id INTEGER, status TEXT)")
    cur.execute(
        "INSERT INTO orders VALUES (1, 'Alice', 100.0), (2, 'Bob', 200.0)"
    )
    cur.execute(
        "INSERT INTO payments VALUES (1, 1, 'paid'), (2, 2, 'pending')"
    )

    user_alias = "paid_amount') UNION SELECT 'injected', 'data', 1.0 FROM orders--"

    query = (
        "SELECT orders.id, orders.customer, "
        f"'' AS \"{user_alias}\" "
        "FROM orders "
        "LEFT OUTER JOIN payments ON orders.id = payments.order_id"
    )
    cur.execute(query)
    print("[VULNERABLE CVE-2025-57833] FilteredRelation alias injection:")
    for row in cur.fetchall():
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    vulnerable_filteredrelation_alias_injection()