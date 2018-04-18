from six import text_type
from django.utils.encoding import force_bytes, force_text
from uuid import UUID
from struct import pack
from base64 import urlsafe_b64encode, urlsafe_b64decode
from allauth.account.models import EmailAddress

def decode_payload_segment(s):
    """
       reference:
           https://github.com/jpadilla/pyjwt/blob/528318787eff3df062f2b55a5f79964aece74f18/jwt/utils.py#L12 
    """
    if isinstance(s, text_type):
        s = s.encode('ascii')
    
    rem = len(s) % 4

    if rem > 0:
        s += b'=' * (4 - rem)

    return urlsafe_b64decode(s)

def parse_token_payload_segment(t):
    """
        reference:
            https://github.com/jpadilla/pyjwt/blob/4f899c6764d57000eba0fc40721f9e1b5d94a77a/jwt/api_jws.py#L130
    """
    t = force_bytes(t)
    try:
        signing_input, crypto_segment = t.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise ValueError('Not enough segments')
    
    return payload_segment

def default_extract_uid_handler(data, app):
    guid = force_bytes(data['guid'])
    raw = urlsafe_b64decode(guid)
    uid = UUID(bytes_le=raw)
    return text_type(uid)

def per_social_app_extract_uid_handler(data, app):
    guid = force_bytes(data['guid'])
    raw = urlsafe_b64decode(guid)
    uid = UUID(bytes_le=raw)
    return "{};{}".format(app.id, uid)

def default_extract_common_fields_handler(data, app):
    upn = data['upn']
    common_fields = dict(
        username = upn.split("@")[0],
        first_name = data.get('first_name'),
        last_name = data.get('last_name'),
        email = data.get('email', upn),
    )
    for key in ("is_staff", "is_superuser", "is_active"):
        common_fields[key] = data.get(key) == "1"
    return common_fields

def per_social_app_extract_common_fields_handler(data, app):
    common_fields = default_extract_common_fields_handler(data, app)
    uid_bytes = UUID(default_extract_uid_handler(data, app)).bytes
    uid_b64 = urlsafe_b64encode(uid_bytes)
    aid_bytes = pack("I", app.id-1)# I format is 0-4294967295
    aid_b64 = urlsafe_b64encode(aid_bytes)
    username = "".join([uid_b64, aid_b64]).replace("=", "")# length of 28
    common_fields["username"] = username
    return common_fields

def default_extract_email_addresses_handler(data, app):
    addressess = []
    common_fields = default_extract_common_fields_handler(data, app)
    email = common_fields.get("email")
    if email:
        addressess.append(EmailAddress(email=email, verified=True, primary=True))
    return addressess

def default_extract_extra_data_handler(data, app):
    return data
