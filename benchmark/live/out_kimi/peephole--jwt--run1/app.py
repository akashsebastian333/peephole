import os

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]


def decode_bearer_token(authorization_header):
    """Decode and verify the Bearer JWT from an Authorization header value.

    Returns the claims dict, or None if the header is missing/malformed or
    the token fails verification.
    """
    scheme, _, token = (authorization_header or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        # algorithms pinned: prevents alg=none / alg-confusion downgrade
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
