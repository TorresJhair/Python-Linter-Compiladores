import sqlite3
from datetime import datetime

def is_valid_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return None

def validate_input(start_date, end_date):
    start_date = is_valid_date(start_date)
    end_date = is_valid_date(end_date)

    if not (start_date and end_date):
        raise ValueError("Invalid date format. Use YYYY-MM-DD.")

    if start_date > end_date:
        raise ValueError("Start date cannot be after end date.")

    return start_date, end_date

def generate_report(db_path, start_date, end_date):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    validated_dates = validate_input(start_date, end_date)

    query = "SELECT * FROM table_name WHERE date_column BETWEEN ? AND ?"
    cursor.execute(query, validated_dates)

    rows = cursor.fetchall()
    for row in rows:
        print(row)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise ValueError("Usage: python script.py <db_path> <start_date> <end_date>")

    db_path, start_date, end_date = sys.argv[1:]
    try:
        generate_report(db_path, start_date, end_date)
    except Exception as e:
        print(f"An error occurred: {e}")