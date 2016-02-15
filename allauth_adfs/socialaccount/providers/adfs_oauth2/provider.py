from django.core.exceptions import ImproperlyConfigured
from allauth.socialaccount import providers
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from .utils import default_extract_extra_data_handler, default_extract_uid_handler, default_extract_common_fields_handler, default_extract_email_addresses_handler

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
    
    def sociallogin_from_response(self, request, response):
        """
        COPIED FROM
        https://github.com/pennersr/django-allauth/blob/5b1cbf485fa363ccb87513545e3b98f3c3bd81fa/allauth/socialaccount/providers/base.py#L52
        TO PASS SocialApp TO EXTRACT METHODS PER
        https://github.com/pennersr/django-allauth/issues/1297
        """
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.models import SocialLogin, SocialAccount

        adapter = get_adapter()
        app = self.get_app(request)
        uid = self.extract_uid(response, app)
        extra_data = self.extract_extra_data(response, app)
        common_fields = self.extract_common_fields(response, app)
        socialaccount = SocialAccount(extra_data=extra_data,
                                      uid=uid,
                                      provider=self.id)
        email_addresses = self.extract_email_addresses(response, app)
        self.cleanup_email_addresses(common_fields.get('email'),
                                     email_addresses)
        sociallogin = SocialLogin(account=socialaccount,
                                  email_addresses=email_addresses)
        user = sociallogin.user = adapter.new_user(request, sociallogin)
        user.set_unusable_password()
        adapter.populate_user(request, sociallogin, common_fields)
        return sociallogin
    
    def extract_extra_data(self, data, app):
        return self.get_settings().get("extract_extra_data_handler", default_extract_extra_data_handler)(data, app)
    
    def extract_uid(self, data, app):
        return self.get_settings().get("extract_uid_handler", default_extract_uid_handler)(data, app)

    def extract_common_fields(self, data, app):
        return self.get_settings().get("extract_common_fields_handler", default_extract_common_fields_handler)(data, app)
    
    def extract_email_addresses(self, data, app):
        return self.get_settings().get("extract_email_addresses_handler", default_extract_email_addresses_handler)(data, app)

providers.registry.register(ADFSOAuth2Provider)