import os
import jwt
from typing import Optional, Dict, Any


def decode_bearer_jwt(authorization_header: str) -> Optional[Dict[str, Any]]:
    """Decode Bearer JWT from Authorization header with signature verification."""
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    key = os.getenv("JWT_HMAC_KEY")

    if not key:
        raise ValueError("JWT_HMAC_KEY environment variable not set")

    try:
        payload = jwt.decode(token, key, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None
