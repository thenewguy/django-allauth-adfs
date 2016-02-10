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