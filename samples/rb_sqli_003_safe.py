def get_report(report_type: str, start_date: str, end_date: str):
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT * FROM reports WHERE type = %s AND created_at BETWEEN %s AND %s',
            [report_type, start_date, end_date]
        )
        return cursor.fetchall()