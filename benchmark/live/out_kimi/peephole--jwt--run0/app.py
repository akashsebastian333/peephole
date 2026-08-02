import os

import jwt

# ponytail: signature verification stays ON — decoding without it accepts
# forged tokens from anyone. Secret comes from the environment, never code.
_SECRET = os.environ["JWT_SECRET"]


def decode_bearer_token(authorization_header):
    """Decode and verify the Bearer JWT from an Authorization header."""
    scheme, _, token = (authorization_header or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("malformed Authorization header")
    return jwt.decode(token, _SECRET, algorithms=["HS256"])
