import jwt


def decode_bearer_token(auth_header):
    """Decode the Bearer JWT from an Authorization header.

    ponytail: signature NOT verified — token is untrusted; only use to
    inspect claims. Verify with a key before trusting for auth decisions.
    """
    token = auth_header.split(" ", 1)[1]
    return jwt.decode(token, options={"verify_signature": False})
