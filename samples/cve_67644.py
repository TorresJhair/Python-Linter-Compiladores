"""
CVE: CVE-2025-67644
Description: LangGraph SQLite Checkpoint SQL injection via metadata filter keys
Source: https://nvd.nist.gov/vuln/detail/CVE-2025-67644
Pattern: LangGraph's _metadata_predicate() function constructs SQL WHERE clauses by
         interpolating metadata filter keys directly into f-strings without validation:
         f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
         An attacker controlling filter keys can inject arbitrary SQL.
"""

import sqlite3


def vulnerable_langgraph_metadata_predicate():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE checkpoints (
            thread_id TEXT,
            checkpoint_id TEXT,
            metadata TEXT,
            checkpoint_data TEXT
        )
    """)
    cur.execute(
        "INSERT INTO checkpoints VALUES "
        "('thread-1', 'ckpt-1', '{\"user_id\": \"alice\"}', 'state_a'), "
        "('thread-1', 'ckpt-2', '{\"user_id\": \"bob\"}', 'state_b'), "
        "('thread-2', 'ckpt-3', '{\"user_id\": \"admin\"}', 'secret_state')"
    )

    metadata_filter = {
        "user_id": "alice",
        "env": "prod"
    }

    predicates = []
    for query_key, query_value in metadata_filter.items():
        predicates.append(
            f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') = '{query_value}'"
        )

    where_clause = " AND ".join(predicates)
    query = f"SELECT thread_id, checkpoint_id, checkpoint_data FROM checkpoints WHERE {where_clause}"

    print(
        "[VULNERABLE CVE-2025-67644] LangGraph _metadata_predicate() filter key injection:"
    )
    print(f"  Generated SQL: {query}")
    for row in cur.execute(query).fetchall():
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    vulnerable_langgraph_metadata_predicate()
