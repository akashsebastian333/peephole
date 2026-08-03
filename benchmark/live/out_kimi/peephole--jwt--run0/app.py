import os

import jwt  # PyJWT

JWT_SECRET = os.environ["JWT_SECRET"]


def decode_bearer_token(authorization_header: str) -> dict:
    """Decode and verify the Bearer JWT from an Authorization header."""
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("expected 'Bearer <token>'")
    # ponytail: signature verification stays ON — verify_signature=False would
    # accept forged tokens; secret comes from env, never hard-coded.
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
