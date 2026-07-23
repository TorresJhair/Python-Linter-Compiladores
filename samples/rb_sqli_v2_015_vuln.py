from django.core.management.base import BaseCommand
import sys

class Command(BaseCommand):
    help = "Bulk-deletes records based on a user-supplied pattern using raw SQL"

    def add_arguments(self, parser):
        parser.add_argument("pattern", type=str, help="Pattern to match for deletion")

    def handle(self, *args, **options):
        pattern = options["pattern"]
        
        try:
            cursor = self.settings.db.connection.cursor()
            query = f"DELETE FROM your_table_name WHERE column_name LIKE %s"
            data = (f"%{pattern}%",)
            cursor.execute(query, data)
            self.stdout.write(self.style.SUCCESS("Successfully deleted records"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error deleting records: {str(e)}"))