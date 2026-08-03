import jwt


def decode_bearer_jwt(authorization_header, key, algorithms=None):
    """Decode and verify a Bearer JWT from the Authorization header.

    The token's signature is verified against `key` using only the explicitly
    allowed `algorithms` (default: HS256). A token whose signature does not
    validate, or which uses an unexpected algorithm, is rejected. Returns None
    if the header is missing/malformed or the token is invalid.
    """
    if algorithms is None:
        algorithms = ["HS256"]

    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        return jwt.decode(token, key, algorithms=algorithms)
    except jwt.PyJWTError:
        return None
