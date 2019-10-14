import logging

from django.core.exceptions import ImproperlyConfigured
from allauth.socialaccount import providers
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from .utils import default_extract_extra_data_handler, default_extract_uid_handler, default_extract_common_fields_handler, default_extract_email_addresses_handler


logger = logging.getLogger(__name__)


class ADFSOAuth2Account(ProviderAccount):
    pass


def log(key, value):
    logger.info('Extracted the following "%s" from this token payload:\n%s', key, value)


class ADFSOAuth2Provider(OAuth2Provider):
    id = 'adfs_oauth2'
    name = 'ADFS Oauth2'
    package = 'allauth_adfs.socialaccount.providers.adfs_oauth2'
    account_class = ADFSOAuth2Account

    def get_auth_params(self, request, action):
        params = super(ADFSOAuth2Provider, self).get_auth_params(request, action)
        if "resource" not in params:
            raise ImproperlyConfigured("'resource' must be supplied as a key of the AUTH_PARAMS dict under adfs_oauth2 in the SOCIALACCOUNT_PROVIDERS setting.")
        return params

    def extract_extra_data(self, data):
        app = self.get_app(self.request)
        extra_data = self.get_settings().get("extract_extra_data_handler", default_extract_extra_data_handler)(data, app)
        log('extra data', extra_data)
        return extra_data

    def extract_uid(self, data):
        app = self.get_app(self.request)
        uid = self.get_settings().get("extract_uid_handler", default_extract_uid_handler)(data, app)
        log('uid', uid)
        return uid

    def extract_common_fields(self, data):
        app = self.get_app(self.request)
        common_fields = self.get_settings().get("extract_common_fields_handler", default_extract_common_fields_handler)(data, app)
        log('common fields', common_fields)
        return common_fields

    def extract_email_addresses(self, data):
        app = self.get_app(self.request)
        email_addresses = self.get_settings().get("extract_email_addresses_handler", default_extract_email_addresses_handler)(data, app)
        # manual string conversion required due to https://github.com/pennersr/django-allauth/issues/2373
        log('email addresses', [e.email for e in email_addresses])
        return email_addresses

provider_classes = [ADFSOAuth2Provider]
