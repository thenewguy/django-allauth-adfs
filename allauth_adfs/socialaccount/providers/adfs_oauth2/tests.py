import json

from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase
from allauth.utils import get_current_site

from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment


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
        app.sites.add(get_current_site())
    
    def test_unencrypted_token_payload(self):
        claims = {
          "guid": "2brp/e0eREqX7SzEA6JjJA==",
          "UPN": "foo@bar.example.com",
          "first_name": "jane",
          "last_name": "doe"
        }
        
        jwt = self.get_dummy_jwt(claims)
        
        encoded_claims_json = parse_token_payload_segment(jwt)
        expected_value = 'eyJVUE4iOiAiZm9vQGJhci5leGFtcGxlLmNvbSIsICJmaXJzdF9uYW1lIjogImphbmUiLCAiZ3Vp\nZCI6ICIyYnJwL2UwZVJFcVg3U3pFQTZKakpBPT0iLCAibGFzdF9uYW1lIjogImRvZSJ9'
        self.assertEqual(encoded_claims_json, expected_value)
        
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
        header_data = json.dumps(header).encode("base64").strip()
        claims_data = json.dumps(claims).encode("base64").strip()
        signature_data = signature.encode("base64").strip()
        payload = [header_data, claims_data, signature_data]
        
        return ".".join(payload)
