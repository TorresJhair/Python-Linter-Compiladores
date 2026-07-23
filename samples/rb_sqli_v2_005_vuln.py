from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Bulk delete records with a given pattern'

    def add_arguments(self, parser):
        parser.add_argument('pattern', type=str, help='User-supplied pattern')

    def handle(self, *args, **options):
        pattern = options['pattern']
        cursor = self.connection.cursor()
        cursor.execute(f'DELETE FROM myapp_mymodel WHERE column_name REGEXP %s', [pattern])
        self.migrate()