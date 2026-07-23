from django.db import connection

def search_logs(search_term: str, level: str):
    with connection.cursor() as cursor:
        cursor.execute(
            f'SELECT timestamp, message FROM logs '
            f'WHERE message LIKE "%{search_term}%" AND level = "{level}"'
        )
        return cursor.fetchall()