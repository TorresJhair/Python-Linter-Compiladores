from django.core.management.base import BaseCommand
import sys

class Command(BaseCommand):
    help = 'Bulk deletes records based on a raw SQL query'

    def add_arguments(self, parser):
        parser.add_argument('pattern', type=str, help='Raw SQL delete pattern')

    def handle(self, *args, **options):
        pattern = options['pattern']

        try:
            with self.settings(DJANGO_SETTINGS_MODULE='your_project_name_here') as settings:
                connection = settings.DATABASES['default'].connection
                cursor = connection.cursor()

                # Parameterized query to prevent SQL Injection
                param_query = pattern.format('param')
                
                for table in tables:
                    if param_query.startswith('DELETE FROM'):
                        parts = param_query.split()
                        for part in parts:
                            if part.upper() == 'FROM':
                                table_name = param_query[parts.index(part)+1:]
                                try:
                                    cursor.execute(param_query, [table_name])
                                    connection.commit()
                                    self.stdout.write(self.style.SUCCESS(f'{table_name} records deleted successfully'))
                                except Exception as e:
                                    self.stderr.write(self.style.ERROR(f'Error deleting records from {table_name}: {e}'))
                    else:
                        self.stdout.write(self.style.NOTICE('Pattern does not start with DELETE FROM. Ignoring...'))

        except Exception as e:
            self.stderr.write(self.style.ERROR(f'An error occurred: {e}'))