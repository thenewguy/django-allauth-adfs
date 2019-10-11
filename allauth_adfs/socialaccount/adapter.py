import logging

from allauth.account.signals import user_logged_in
from allauth.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter, get_adapter
from allauth.socialaccount.providers import registry
from django.contrib import messages
from django.dispatch import receiver
from django.http import HttpResponseForbidden
from .providers.adfs_oauth2.provider import ADFSOAuth2Provider


logger = logging.getLogger(__name__)


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def authentication_error(self,
                             request,
                             provider_id,
                             error=None,
                             exception=None,
                             extra_context=None):
        """
        Invoked when there is an error in the authentication cycle. In this
        case, pre_social_login will not be reached.
        You can use this hook to intervene, e.g. redirect to an
        educational flow by raising an ImmediateHttpResponse.
        """
        logger.error("\n\n".join([
            "Error with request: %(request)r",
            "For provider: %(provider_id)s",
            "Error: %(error)s",
            "Exception: %(exception)r",
            "Extra context: %(extra_context)s",
        ]) % {
            "request": request,
            "provider_id": provider_id,
            "error": error,
            "exception": exception,
            "extra_context": extra_context,
        })

    def pre_social_login(self, request, sociallogin):
        # new user logins are handled by populate_user
        if sociallogin.is_existing:
            changed, user = self.update_user_fields(request, sociallogin)
            if changed:
                user.save()

    def populate_user(self, request, sociallogin, data):
        user = super(SocialAccountAdapter, self).populate_user(request, sociallogin, data)
        self.update_user_fields(request, sociallogin, user)
        return user

    def update_user_fields(self, request, sociallogin=None, user=None):
        changed = False
        if user is None:
            user = sociallogin.account.user
        adfs_provider = registry.by_id(ADFSOAuth2Provider.id, request)

        false_keys = ["is_staff", "is_superuser"]
        boolean_keys = false_keys + ["is_active"]
        copy_keys = boolean_keys + ["first_name", "last_name", "email"]

        if sociallogin is not None and sociallogin.account.provider == ADFSOAuth2Provider.id:
            data = sociallogin.account.extra_data
            values = adfs_provider.extract_common_fields(data)
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
                    msg = "Staff users must authenticate via the %s provider!" % adfs_provider.name
                    response = HttpResponseForbidden(msg)
                    raise ImmediateHttpResponse(response)

        return changed, user
