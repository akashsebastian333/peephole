"""JWT decoding helpers (signature verification enabled)."""

import os

import jwt


def decode_bearer_jwt(authorization_header, key=None, algorithms=None):
    """Decode and verify the Bearer JWT from an Authorization header value.

    Expects a header of the form ``Bearer <token>``. Verifies the token's
    signature against ``key`` using one of ``algorithms`` (default RS256).
    Returns the decoded claims dict, or ``None`` if the header is missing or
    malformed. Raises ``jwt.PyJWTError`` subclasses on invalid/expired tokens.
    """
    if not authorization_header:
        return None

    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1].strip()
    if not token:
        return None

    if key is None:
        key = os.environ["JWT_PUBLIC_KEY"]
    if algorithms is None:
        algorithms = ["RS256"]

    return jwt.decode(token, key, algorithms=algorithms)
