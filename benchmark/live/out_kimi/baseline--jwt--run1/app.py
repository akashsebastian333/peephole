"""JWT decoding helper. NOTE: signature verification is disabled —
do NOT use the returned claims for authentication/authorization decisions."""

import jwt


def decode_bearer_jwt(authorization: str) -> dict:
    """Decode the Bearer JWT from an Authorization header without verifying the signature."""
    token = authorization.removeprefix("Bearer ").strip()
    return jwt.decode(token, options={"verify_signature": False})
