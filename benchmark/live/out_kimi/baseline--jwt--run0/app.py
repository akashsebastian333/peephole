import jwt


def decode_bearer(authorization):
    """Decode a Bearer JWT from an Authorization header value.

    ponytail: signature verification disabled per spec — do not use in
    production; add key/algorithms + drop options to verify.
    """
    token = authorization.removeprefix("Bearer ").strip()
    return jwt.decode(token, options={"verify_signature": False})
