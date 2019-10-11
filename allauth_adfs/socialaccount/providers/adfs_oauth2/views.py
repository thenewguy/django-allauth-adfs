import logging
import json

from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter,
                                                          OAuth2LoginView,
                                                          OAuth2CallbackView)
from django.core.exceptions import ImproperlyConfigured
from django.utils.six import string_types
from django.utils.encoding import force_bytes
from .provider import ADFSOAuth2Provider
from .utils import decode_payload_segment, parse_token_payload_segment
import requests
from xml.dom.minidom import parseString
from hashlib import md5

try:
    from urllib.parse import urlunsplit
except ImportError:
    from urlparse import urlunsplit

try:
    import jwt
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except ImportError:
    JWT_AVAILABLE = False
else:
    JWT_AVAILABLE = True

from .compat import caches, DEFAULT_CACHE_ALIAS


logger = logging.getLogger(__name__)


class ADFSOAuth2Adapter(OAuth2Adapter):
    provider_id = ADFSOAuth2Provider.id

    def get_setting(self, key, default="", required=True):
        value = self.get_provider().get_settings().get(key, default)
        if not value and required:
            raise ImproperlyConfigured("ADFS OAuth2 provider setting '%s' is required.  It must not be falsey." % key)
        return value

    @property
    def redirect_uri_protocol(self):
        value = self.get_setting("redirect_uri_protocol", default=None, required=False)
        if isinstance(value, string_types):
            value = value.lower()
        if value not in ("http", "https", None):
            raise ImproperlyConfigured("ADFS OAuth2 provider setting 'redirect_uri_protocol' must be one of 'http', 'https', or None. You supplied '%s'." % value)
        return value

    @property
    def host(self):
        """
            e.g. sso.internal.example.com or sso.example.com:8443
        """
        return self.get_setting("host")

    def construct_adfs_url(self, path):
        parts = (
            "https",
            self.host,
            path,
            "",
            "",
        )
        return urlunsplit(parts)

    @property
    def access_token_url(self):
        return self.construct_adfs_url("/adfs/oauth2/token")

    @property
    def authorize_url(self):
        return self.construct_adfs_url("/adfs/oauth2/authorize")

    @property
    def federation_metadata_url(self):
        return self.construct_adfs_url("/FederationMetadata/2007-06/FederationMetadata.xml")

    @property
    def federation_metadata_xml(self):
        response = requests.get(self.federation_metadata_url)

        if response.status_code == 200:
            data = response.content
        else:
            raise RuntimeError("Could not retrieve federation metadata")

        xml = parseString(data)

        return xml

    @property
    def token_signature_key(self):
        cache_alias = self.get_setting("token_signature_key_cache_alias", DEFAULT_CACHE_ALIAS)
        cache = caches[cache_alias]
        hashable_url = force_bytes(self.federation_metadata_url)
        cache_key = ":".join([
            "allauth_adfs",
            "ADFSOAuth2Adapter",
            md5(hashable_url).hexdigest(),
            "token_signature_key",
        ])

        pub = cache.get(cache_key)

        if pub is None:
            xml = self.federation_metadata_xml

            signature = xml.getElementsByTagName("ds:Signature")[0]
            cert_b64 = signature.getElementsByTagName("X509Certificate")[0].firstChild.nodeValue

            cert_str = decode_payload_segment(cert_b64)
            cert_obj = load_der_x509_certificate(cert_str, default_backend())

            pub = cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            timeout = self.get_setting("token_signature_key_cache_timeout", 0, required=False)
            cache.set(cache_key, pub, timeout)

        return pub

    def complete_login(self, request, app, token, **kwargs):
        verify_token = self.get_setting("verify_token", True, required=False)

        if verify_token:
            if not JWT_AVAILABLE:
                raise ImproperlyConfigured("ADFS OAuth2 cannot verify tokens without the `PyJWT` and `cryptography` packages.  They can both be installed with pip.  The `cryptography` package requires development headers for python and libffi.  They can be installed with 'apt-get install python-dev libffi-dev' on Ubuntu Linux.  You can disable token verification by setting 'verify_token' to False under the 'adfs_oauth2' socialaccount provider configuration dictionary in `settings.py`.  IT IS NOT RECOMMENDED TO DISABLE TOKEN VERIFICATION IN PRODUCTION!")

            kwargs = {"verify": verify_token}

            auth_params = self.get_setting("AUTH_PARAMS")

            try:
                kwargs["audience"] = "microsoft:identityserver:%s" % auth_params["resource"]
            except KeyError:
                raise ImproperlyConfigured("ADFS OAuth2 AUTH_PARAMS setting 'resource' must be specified.")

            kwargs["leeway"] = self.get_setting("time_validation_leeway", 0, required=False)

            kwargs["key"] = self.token_signature_key

            payload = jwt.decode(token.token, **kwargs)

        else:
            encoded_data = parse_token_payload_segment(token.token)
            data = decode_payload_segment(encoded_data)
            payload = json.loads(data)

        logger.info("Retrieved the following token payload from %s:\n%s", self.host, payload)

        return self.get_provider().sociallogin_from_response(
            request,
            payload
        )

oauth_login = OAuth2LoginView.adapter_view(ADFSOAuth2Adapter)
oauth_callback = OAuth2CallbackView.adapter_view(ADFSOAuth2Adapter)
