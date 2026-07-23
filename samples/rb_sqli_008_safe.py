def search_logs(search_term: str, level: str):
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT timestamp, message FROM logs WHERE message LIKE %s AND level = %s',
            [f'%{search_term}%', level]
        )
        return cursor.fetchall()