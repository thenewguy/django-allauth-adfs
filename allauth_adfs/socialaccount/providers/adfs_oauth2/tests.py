import base64
import json
import six

from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase
from django.contrib.sites.models import Site

from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment


def encode(source):
    if six.PY3:
        source = source.encode('utf-8')
    content = base64.b64encode(source).decode('utf-8')
    return content.strip()


class ADFSTests(TestCase):
    provider_id = ADFSOAuth2Provider.id
    
    def setUp(self):
        super(ADFSTests, self).setUp()
        self.provider = providers.registry.by_id(self.provider_id)
        app = SocialApp.objects.create(provider=self.provider.id,
                                       name=self.provider.id,
                                       client_id='app123id',
                                       key=self.provider.id,
                                       secret='dummy')
        app.sites.add(Site.objects.get_current())
    
    def test_unencrypted_token_payload(self):
        claims = {
          "guid": "2brp/e0eREqX7SzEA6JjJA==",
          "UPN": "foo@bar.example.com",
          "first_name": "jane",
          "last_name": "doe"
        }
        
        jwt = self.get_dummy_jwt(claims)
        
        encoded_claims_json = parse_token_payload_segment(jwt)
        decoded_claims_json = decode_payload_segment(encoded_claims_json)
        parsed_claims = json.loads(decoded_claims_json)
        
        self.assertEqual(claims["guid"], parsed_claims["guid"])
        self.assertEqual(claims["UPN"], parsed_claims["UPN"])
        self.assertEqual(claims["first_name"], parsed_claims["first_name"])
        self.assertEqual(claims["last_name"], parsed_claims["last_name"])
    
    def get_dummy_jwt(self, claims):
        # raw data
        header = {
            "alg": "none",
            "typ":"JWT"
        }
        
        signature = ""
        
        # payload data
        header_data = encode(json.dumps(header))
        claims_data = encode(json.dumps(claims))
        signature_data = encode(signature)
        payload = [header_data, claims_data, signature_data]
        
        return ".".join(payload)
