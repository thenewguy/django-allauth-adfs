from allauth.socialaccount.providers.oauth.urls import default_urlpatterns

from .provider import ADFSOAuth2Provider

urlpatterns = default_urlpatterns(ADFSOAuth2Provider)