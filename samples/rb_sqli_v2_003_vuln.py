import sqlite3
import sys

def generate_report(db_path, start_date, end_date):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    start_date_arg = f"%{start_date}"
    end_date_arg = f"%{end_date}"

    cursor.execute("SELECT * FROM your_table WHERE date_column BETWEEN ? AND ?", (start_date_arg, end_date_arg))
    rows = cursor.fetchall()
    
    for row in rows:
        print(row)
        
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <db_path> <start_date> <end_date>")
        sys.exit(1)

    db_path = sys.argv[1]
    start_date = sys.argv[2]
    end_date = sys.argv[3]

    generate_report(db_path, start_date, end_date)