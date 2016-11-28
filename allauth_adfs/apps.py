from django.apps import AppConfig, apps


class DefaultConfig(AppConfig):
    name = "allauth_adfs"

    def ready(self):
        from .socialaccount.providers.adfs_oauth2.provider import ADFSOAuth2Provider
