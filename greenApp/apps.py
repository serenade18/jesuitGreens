from django.apps import AppConfig


class GreenappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'greenApp'

    def ready(self):
        import greenApp.signals
