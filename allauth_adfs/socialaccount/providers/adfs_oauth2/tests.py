from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase

from .provider import ADFSOAuth2Provider


class ADFSTests(OAuth2TestsMixin, TestCase):
    provider_id = ADFSOAuth2Provider.id

    def get_mocked_response(self):
        raise NotImplementedError()
