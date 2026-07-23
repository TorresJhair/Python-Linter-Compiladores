from flask import request
import psycopg2

def search_endpoint():
    conn = psycopg2.connect("dbname=test user=postgres password=secret")
    cur = conn.cursor()
    
    query_term = request.args.get('q')
    
    if query_term:
        # Replace with your table and column names
        query = f"SELECT * FROM my_table WHERE text_column LIKE %s"
        cur.execute(query, ('%' + query_term + '%',))
        
        results = cur.fetchall()
        
        for row in results:
            print(row)
    
    conn.close()