from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
 
class Command(BaseCommand):
    """
    Create a superuser if none exist
    Example:
        manage.py createsuperuser_if_none_exists --user=admin --password=changeme
    """
 
    def add_arguments(self, parser):
        parser.add_argument("--user", required=True, help="Specifies the username for the superuser.")
        parser.add_argument("--password", required=True, help="Specifies the password for the superuser.")
        parser.add_argument("--email", default="admin@example.com", help="Specifies the email for the superuser.")
 
    def handle(self, *args, **options):
        username = options["user"]
        password = options["password"]
        email = options["email"]
 
        User = get_user_model()
        if User.objects.filter(username=username).exists():
            self.stdout.write("User exists, exiting...")
            return
        User.objects.create_superuser(username=username, password=password, email=email)
 
        self.stdout.write(f'Local superadmin user "{username}" was created')