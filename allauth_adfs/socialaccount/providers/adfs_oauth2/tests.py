from __future__ import print_function

import base64
import json
import socket
import six
import unittest
from xml.parsers.expat import ExpatError

import requests
from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.templatetags.socialaccount import get_providers
from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse
from django.conf import settings
from django.contrib.sites.models import Site
from django.template import RequestContext, Template
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from django.urls import reverse

from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment, default_extract_uid_handler
from .views import ADFSOAuth2Adapter


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


class ADFSTests(OAuth2TestsMixin):
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


#
# INTEGRATION TESTS REQUIRE AN ACTUAL ADFS SERVER
# THIS ALLOWS US TO RUN TESTS IF THE SERVER IS AVAIALBLE
# LOCALLY BUT STILL RUN OTHER TESTS ON TRAVIS. USE
# HOSTNAME EXPANSION INSTEAD OF HARDCODING THE INTERNAL
# ADFS SERVER ADDRESS. CHECK IS CURR
#
ADFS_SERVER_CNAME = 'sso'
ADFS_SERVER_HOSTNAME = socket.getfqdn(ADFS_SERVER_CNAME)
ADFS_SERVER_DOMAIN_LIST = ADFS_SERVER_HOSTNAME.split('.')[1:]
ADFS_SERVER_DOMAIN = ".".join(ADFS_SERVER_DOMAIN_LIST)
ADFS_SERVER_FQDN = "%s.%s" % (ADFS_SERVER_CNAME, ADFS_SERVER_DOMAIN)

try:
    requests.get('http://%s' % ADFS_SERVER_FQDN, timeout=1)
except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
    ADFS_AVAILABLE = False
    print("\nADFS is not available at '%s'. Exception:\n%r\n" % (ADFS_SERVER_FQDN, e))
else:
    ADFS_AVAILABLE = True


@unittest.skipUnless(ADFS_AVAILABLE, "requires reachable ADFS server")
@override_settings(SOCIALACCOUNT_PROVIDERS = {
    'adfs_oauth2': {
        'name': 'ADFS Login',
        'host': ADFS_SERVER_FQDN,
        'redirect_uri_protocol': 'http',
        'time_validation_leeway': 30,  # allow for 30 seconds of clock drift
        'verify_token': True,
        'AUTH_PARAMS': {
            'resource': 'integration-tests',
        },
    }
})
class IntegrationADFSTests(OAuth2TestsMixin, TestCase):
    provider_id = ADFSOAuth2Provider.id
    
    def setUp(self):
        super(IntegrationADFSTests, self).setUp()
        factory = RequestFactory()
        request = factory.get('/accounts/login/')
        adapter = ADFSOAuth2Adapter(request=request)
        self.adapter = adapter
    
    def get_mocked_response(self):
        return MockedResponse(200, '')
    
    @unittest.skip("refresh tokens are not supported")
    def test_account_refresh_token_saved_next_login(self, **kwargs):
        pass

    @unittest.skip("cannot match expected token value")
    def test_account_tokens(self, **kwargs):
        pass
    
    def test_login(self, **kwargs):
        # we cannot actually log in, so the xml returned is blank and fails
        # but this tests the process up to that point and we were having exceptions
        # prior to that point when converting to python3 so this is better than nothing
        with self.assertRaises(ExpatError):
            super(IntegrationADFSTests, self).test_login(**kwargs)
    
    def test_verify_true(self):
        self.assertTrue(settings.SOCIALACCOUNT_PROVIDERS['adfs_oauth2']['verify_token'])
    
    def test_access_token_url(self):
        expected = "https://%s/adfs/oauth2/token" % ADFS_SERVER_FQDN
        self.assertEquals(self.adapter.access_token_url, expected)
    
    def test_token_signature_key(self):
        # this varies, but confirm we get a truthy value and the code runs
        self.assertTrue(self.adapter.token_signature_key)
    
    def test_federation_metadata_xml(self):
        self.assertTrue(self.adapter.federation_metadata_xml)
