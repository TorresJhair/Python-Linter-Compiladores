import sqlite3
import sys

def generate_report(db_path, start_date, end_date):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    query = f"SELECT * FROM table_name WHERE date_column BETWEEN ? AND ?"
    cursor.execute(query, (start_date, end_date))

    rows = cursor.fetchall()
    for row in rows:
        print(row)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <db_path> <start_date> <end_date>")
        sys.exit(1)

    db_path, start_date, end_date = sys.argv[1:]
    generate_report(db_path, start_date, end_date)