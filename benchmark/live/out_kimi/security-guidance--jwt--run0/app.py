import jwt  # PyJWT


def decode_bearer(authorization: str):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("expected 'Authorization: Bearer <jwt>'")
    return jwt.decode(token, options={"verify_signature": False})
