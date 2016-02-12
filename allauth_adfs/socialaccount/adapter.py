from allauth.account.signals import user_logged_in
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter, get_adapter
from allauth.socialaccount.providers import registry
from django.contrib import messages
from django.dispatch import receiver
from .providers.adfs_oauth2.provider import ADFSOAuth2Provider

class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        # new user logins are handled by populate_user
        if sociallogin.is_existing:
            changed, user = self.update_user_fields(sociallogin)
            if changed:
                user.save()

    def populate_user(self, request, sociallogin, data):
        user = super(SocialAccountAdapter, self).populate_user(request, sociallogin, data)
        self.update_user_fields(sociallogin, user)
        return user
    
    def update_user_fields(self, sociallogin=None, user=None):
        changed = False
        if user is None:
            user = sociallogin.account.user
        
        false_keys = ["is_staff", "is_superuser"]
        boolean_keys = false_keys + ["is_active"]
        copy_keys = boolean_keys + ["first_name", "last_name", "email"]
        
        if sociallogin is not None and sociallogin.account.provider == ADFSOAuth2Provider.id:
            provider = registry.by_id(sociallogin.account.provider)
            data = sociallogin.account.extra_data
            values = provider.extract_common_fields(data)
            for key in copy_keys:
                # it is assumed that values are cleaned and set for all
                # fields and if any of the boolean_keys are not provided
                # in the raw data they should be set to False by
                # the extract_common_fields method
                if getattr(user, key) != values[key]:
                    setattr(user, key, values[key])
                    changed = True
        else:
            for key in false_keys:
                if getattr(user, key):
                    setattr(user, key, False)
                    changed = True
        
        return changed, user

@receiver(user_logged_in)
def ensure_staff_login_via_adfs(**kwargs):
    adapter = get_adapter()
    if isinstance(adapter, SocialAccountAdapter):
        sociallogin = kwargs.get("sociallogin")
        via_adfs = sociallogin and sociallogin.account.provider == ADFSOAuth2Provider.id
        if not via_adfs:
            changed, user = adapter.update_user_fields(kwargs["user"])
            if changed:
                user.save()
                provider = registry.by_id(ADFSOAuth2Provider.id)
                messages.warning(kwargs["request"], 'User account modified due to log in provider. Log in with the %s provider to restore functionality when needed.' % provider.name)
