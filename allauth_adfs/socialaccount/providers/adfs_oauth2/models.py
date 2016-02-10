from django.dispatch import receiver
from uuid import UUID
from allauth.account.models import EmailAddress
from .signals import extract_uid_signal, extract_common_fields_signal, extract_email_addresses_signal

@receiver(extract_uid_signal, dispatch_uid="default_extract_uid_receiver")
def extract_uid_receiver(sender, data, **kwargs):
    raw = data.get('ppid').decode("base64")
    uid = UUID(bytes_le=raw)
    return unicode(uid)

@receiver(extract_common_fields_signal, dispatch_uid="default_extract_common_fields_receiver")
def extract_common_fields_receiver(sender, data, **kwargs):
    return dict(
        username = data.get('upn').split("@")[0],
        first_name = data.get('given_name'),
        last_name = data.get('family_name'),
    )

@receiver(extract_email_addresses_signal, dispatch_uid="default_extract_email_addresses_receiver")
def extract_email_addresses_receiver(sender, data, **kwargs):
    return [EmailAddress(email=data.get('upn'), verified=True, primary=True)]