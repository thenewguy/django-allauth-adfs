from django.core.exceptions import ImproperlyConfigured
from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from .signals import extract_uid_signal, extract_common_fields_signal, extract_email_addresses_signal

class ADFSOAuth2Account(ProviderAccount):
    pass

class ADFSOAuth2Provider(OAuth2Provider):
    id = 'adfs_oauth2'
    package = 'allauth_adfs.socialaccount.providers.adfs_oauth2'
    account_class = ADFSOAuth2Account
    
    @property
    def name(self):
        return self.get_settings().get("name", "ADFS Oauth2")
    
    def signal_responses_handler(self, label, responses):
        responses_len = len(responses)
        if not responses_len:
            raise ImproperlyConfigured("No `%s` receivers responded." % label)
        elif 1 < responses_len:
            senders = [response[1] for response in responses]
            raise ImproperlyConfigured("Too many `%s` receivers responded... THERE CAN ONLY BE ONE!  Disconnect unwanted signals.  Reference `https://docs.djangoproject.com/en/1.7/topics/signals/#django.dispatch.Signal`.  Detected the following senders: %s" % (label, ", ".join(senders)))
        return responses[0][1]
    
    def extract_uid(self, data):
        responses = extract_uid_signal.send(sender=self, data=data)
        return self.signal_responses_handler("extract_uid", responses)

    def extract_common_fields(self, data):
        responses = extract_common_fields_signal.send(sender=self, data=data)
        return self.signal_responses_handler("extract_common_fields", responses)
    
    def extract_email_addresses(self, data):
        responses = extract_email_addresses_signal.send(sender=self, data=data)
        return self.signal_responses_handler("extract_email_addresses", responses)

providers.registry.register(ADFSOAuth2Provider)