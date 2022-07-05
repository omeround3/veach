from django.apps import AppConfig
from core.db.db_init import init_db


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        import core.signals
        init_db()