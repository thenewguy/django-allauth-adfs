import base64
import json
import six

from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.templatetags.socialaccount import get_providers
from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase
from django.contrib.sites.models import Site
from django.template import RequestContext, Template
from django.test.client import RequestFactory

from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment


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
