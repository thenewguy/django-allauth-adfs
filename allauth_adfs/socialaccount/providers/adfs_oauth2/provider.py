from django.core.exceptions import ImproperlyConfigured
from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from .utils import default_extract_uid_handler, default_extract_common_fields_handler, default_extract_email_addresses_handler

class ADFSOAuth2Account(ProviderAccount):
    pass

class ADFSOAuth2Provider(OAuth2Provider):
    id = 'adfs_oauth2'
    package = 'allauth_adfs.socialaccount.providers.adfs_oauth2'
    account_class = ADFSOAuth2Account
    
    @property
    def name(self):
        return self.get_settings().get("name", "ADFS Oauth2")
    
    def get_auth_params(self, request, action):
        params = super(ADFSOAuth2Provider, self).get_auth_params(request, action)
        if "resource" not in params:
            raise ImproperlyConfigured("'resource' must be supplied as a key of the AUTH_PARAMS dict under adfs_oauth2 in the SOCIALACCOUNT_PROVIDERS setting.")
        return params
    
    def extract_uid(self, data):
        return self.get_settings().get("extract_uid_handler", default_extract_uid_handler)(data)

    def extract_common_fields(self, data):
        return self.get_settings().get("extract_common_fields_handler", default_extract_common_fields_handler)(data)
    
    def extract_email_addresses(self, data):
        return self.get_settings().get("extract_email_addresses_handler", default_extract_email_addresses_handler)(data)

providers.registry.register(ADFSOAuth2Provider)