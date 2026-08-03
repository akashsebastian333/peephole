import jwt


def decode_bearer_token(authorization_header):
    scheme, _, token = (authorization_header or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("missing or malformed bearer token")
    return jwt.decode(token, options={"verify_signature": False})
