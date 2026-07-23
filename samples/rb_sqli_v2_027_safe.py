from flask import Flask, request, escape
import psycopg2

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    conn = psycopg2.connect(
        dbname=escape("your_dbname"),
        user=escape("your_username"),
        password=escape("your_password"),
        host=escape("your_host"),
        port="your_port"
    )
    cur = conn.cursor()
    
    query_term = request.args.get('q')
    if not query_term:
        return {"error": "Query term is required"}
        
    # input validation
    query_term = escape(query_term)

    query = f"SELECT * FROM your_table WHERE your_column ILIKE %s;"

    cur.execute(query, (f'%{query_term}%',))
    results = cur.fetchall()

    return {'results': [row[0] for row in results]}

if __name__ == '__main__':
    app.run()