import os
import jwt
from jwt import InvalidTokenError


def decode_bearer_token(auth_header: str) -> dict:
    """Decode a Bearer JWT from the Authorization header with signature verification."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise ValueError("Invalid Authorization header")

    token = auth_header[7:]

    secret = os.getenv("JWT_HMAC_KEY")
    if not secret:
        raise ValueError("JWT_HMAC_KEY environment variable not set")

    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"])
        return claims
    except InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")
