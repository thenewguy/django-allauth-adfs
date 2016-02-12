from uuid import UUID
from allauth.account.models import EmailAddress

def decode_payload_segment(s):
    """
       reference:
           https://github.com/jpadilla/pyjwt/blob/528318787eff3df062f2b55a5f79964aece74f18/jwt/utils.py#L12 
    """
    rem = len(s) % 4

    if rem > 0:
        s += b'=' * (4 - rem)

    return s.decode("base64")

def parse_token_payload_segment(t):
    """
        reference:
            https://github.com/jpadilla/pyjwt/blob/4f899c6764d57000eba0fc40721f9e1b5d94a77a/jwt/api_jws.py#L130
    """
    try:
        signing_input, crypto_segment = t.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise ValueError('Not enough segments')
    
    return payload_segment

def default_extract_uid_handler(data):
    raw = data['guid'].decode("base64")
    uid = UUID(bytes_le=raw)
    return unicode(uid)

def default_extract_common_fields_handler(data):
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

def default_extract_email_addresses_handler(data):
    addressess = []
    common_fields = default_extract_common_fields_handler(data)
    email = common_fields.get("email")
    if email:
        addressess.append(EmailAddress(email=email, verified=True, primary=True))
    return addressess