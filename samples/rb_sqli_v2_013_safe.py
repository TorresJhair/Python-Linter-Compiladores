import sqlite3
from datetime import datetime

def validate_date(date_text):
    try:
        datetime.strptime(date_text, "%Y-%m-%d")
        return True
    except ValueError:
        return False

def generate_report(db_path, start_date, end_date):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if not validate_date(start_date) or not validate_date(end_date):
        print("Invalid date format. Please use YYYY-MM-DD.")
        return

    query = "SELECT * FROM your_table WHERE date BETWEEN ? AND ?"
    cursor.execute(query, (start_date, end_date))

    results = cursor.fetchall()

    for row in results:
        print(row)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <db_path> <start_date> <end_date>")
        sys.exit(1)
    
    db_path, start_date, end_date = sys.argv[1:]
    generate_report(db_path, start_date, end_date)