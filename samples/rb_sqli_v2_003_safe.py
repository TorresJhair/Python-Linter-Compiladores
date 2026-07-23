import sqlite3
import sys

def validate_input(input_str):
    try:
        datetime.datetime.strptime(input_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def generate_report(db_path, start_date, end_date):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if not validate_input(start_date) or not validate_input(end_date):
        print("Invalid date format. Please use YYYY-MM-DD.")
        return
    
    try:
        start_date_arg = datetime.datetime.strptime(start_date, '%Y-%m-%d').strftime('%s')
        end_date_arg = datetime.datetime.strptime(end_date, '%Y-%m-%d').strftime('%s')
        
        cursor.execute("SELECT * FROM your_table WHERE date_column BETWEEN ? AND ?", (start_date_arg, end_date_arg))
        rows = cursor.fetchall()
        
        for row in rows:
            print(row)
            
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <db_path> <start_date> <end_date>")
        sys.exit(1)

    db_path = sys.argv[1]
    start_date = sys.argv[2]
    end_date = sys.argv[3]

    generate_report(db_path, start_date, end_date)