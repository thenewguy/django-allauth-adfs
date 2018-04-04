import base64
import json
import six
import unittest

from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.templatetags.socialaccount import get_providers
from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase
from django.conf import settings
from django.contrib.sites.models import Site
from django.template import RequestContext, Template
from django.test.client import RequestFactory
from django.urls import reverse

from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment, default_extract_uid_handler


def encode(source):
    if six.PY3:
        source = source.encode('utf-8')
    content = base64.b64encode(source).decode('utf-8')
    return content.strip()


class TestProviderUrls(TestCase):
    def test_urls_importable(self):
        from allauth_adfs.socialaccount.providers.adfs_oauth2 import urls
    
    def test_urls_populated(self):
        from allauth_adfs.socialaccount.providers.adfs_oauth2 import urls
        self.assertIsInstance(urls.urlpatterns, list)
        self.assertTrue(urls.urlpatterns)
        
    def test_login_url(self):
        registry = providers.ProviderRegistry()
        registry.load()
        provider = registry.by_id(ADFSOAuth2Provider.id)
        login_url = provider.get_login_url(request=None)
        self.assertEquals(login_url, "/accounts/adfs_oauth2/login/")
    
    def test_template_login_url(self):
        registry = providers.ProviderRegistry()
        registry.load()
        provider = registry.by_id(ADFSOAuth2Provider.id)
        
        factory = RequestFactory()
        request = factory.get('/accounts/login/')
        c = RequestContext(request, {
            'provider': provider,
        })
        t = Template("""
            {% load socialaccount %}
            {% provider_login_url provider.id %}
        """)
        content = t.render(c).strip()
        
        self.assertEquals(content, "/accounts/adfs_oauth2/login/")


class TestProvidersRegistryFindsUs(TestCase):
    def test_load(self):
        registry = providers.ProviderRegistry()
        self.assertFalse(registry.loaded)
        self.assertFalse(registry.provider_map)
        self.assertNotIn(ADFSOAuth2Provider.id, registry.provider_map)
        registry.load()
        self.assertIn(ADFSOAuth2Provider.id, registry.provider_map)
        provider = registry.by_id(ADFSOAuth2Provider.id)
        self.assertIsInstance(provider, ADFSOAuth2Provider)


class UtilsTests(TestCase):
    def test_guid(self):
        data = {"guid": "2brp/e0eREqX7SzEA6JjJA=="}
        uid = default_extract_uid_handler(data, None)
        self.assertEquals(uid, six.text_type('fde9bad9-1eed-4a44-97ed-2cc403a26324'))
        


class ADFSTests(OAuth2TestsMixin, TestCase):
    provider_id = ADFSOAuth2Provider.id
    default_claims = {
        "guid": "2brp/e0eREqX7SzEA6JjJA==",
        "upn": "foo@bar.example.com",
        "first_name": "jane",
        "last_name": "doe"
    }
    
    def get_mocked_response(self):
        return MockedResponse(200, '')
    
    def get_login_response_json(self, **kwargs):
        jwt = self.get_dummy_jwt()
        return '{"access_token":"%s"}' % jwt
    
    def test_unencrypted_token_payload(self):
        jwt = self.get_dummy_jwt()
        
        encoded_claims_json = parse_token_payload_segment(jwt)
        decoded_claims_json = decode_payload_segment(encoded_claims_json)
        parsed_claims = json.loads(decoded_claims_json)
        
        claims = self.default_claims
        
        self.assertEqual(claims["guid"], parsed_claims["guid"])
        self.assertEqual(claims["upn"], parsed_claims["upn"])
        self.assertEqual(claims["first_name"], parsed_claims["first_name"])
        self.assertEqual(claims["last_name"], parsed_claims["last_name"])
    
    @unittest.skip("refresh tokens are not supported")
    def test_account_refresh_token_saved_next_login(self, **kwargs):
        pass
    
    @unittest.skip("cannot match expected token value")
    def test_account_tokens(self, **kwargs):
        pass
    
    def get_dummy_jwt(self, claims=None):
        if claims is None:
            claims = self.default_claims
        
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
