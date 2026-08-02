import os
from typing import Optional, Dict, Any
import jwt


def decode_bearer_token(auth_header: Optional[str]) -> Optional[Dict[str, Any]]:
    """Decode and verify Bearer JWT from Authorization header."""
    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    key = os.getenv("JWT_HMAC_KEY")
    if not key:
        raise ValueError("JWT_HMAC_KEY environment variable not set")

    try:
        payload = jwt.decode(token, key, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None
