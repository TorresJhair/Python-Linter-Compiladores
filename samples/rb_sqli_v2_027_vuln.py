from flask import Flask, request
import psycopg2

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    conn = psycopg2.connect(
        dbname="your_dbname",
        user="your_username",
        password="your_password",
        host="your_host",
        port="your_port"
    )
    cur = conn.cursor()
    
    query_term = request.args.get('q')
    query = f"SELECT * FROM your_table WHERE your_column ILIKE '%{query_term}%';"

    cur.execute(query)
    results = cur.fetchall()

    return {'results': [row[0] for row in results]}

if __name__ == '__main__':
    app.run()