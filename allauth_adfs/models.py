from allauth.account.signals import user_logged_in
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter, get_adapter
from allauth.socialaccount.providers import registry
from django.contrib import messages
from django.dispatch import receiver
from .socialaccount.providers.adfs_oauth2.provider import ADFSOAuth2Provider
from .socialaccount.adapter import SocialAccountAdapter

@receiver(user_logged_in)
def ensure_staff_login_via_adfs(**kwargs):
    adapter = get_adapter()
    if isinstance(adapter, SocialAccountAdapter):
        sociallogin = kwargs.get("sociallogin")
        via_adfs = sociallogin and sociallogin.account.provider == ADFSOAuth2Provider.id
        if not via_adfs:
            changed, user = adapter.update_user_fields(kwargs["request"], user=kwargs["user"])
            if changed:
                user.save()
                provider = registry.by_id(ADFSOAuth2Provider.id)
                messages.warning(kwargs["request"], 'User account modified due to log in provider. Log in with the %s provider to restore functionality when needed.' % provider.name)
