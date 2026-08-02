import os

import jwt


# Public key used to verify token signatures. Configure via environment.
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = "RS256"


def decode_bearer_token(authorization_header):
    """Decode and verify the Bearer JWT from an Authorization header."""
    if not authorization_header:
        raise ValueError("missing Authorization header")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Authorization header is not a valid Bearer token")

    token = parts[1]
    return jwt.decode(token, JWT_PUBLIC_KEY, algorithms=[JWT_ALGORITHM])
