import jwt
from typing import Optional, Dict, Any


def decode_bearer_jwt(authorization_header: Optional[str]) -> Dict[str, Any]:
    """Decode JWT from Bearer token in Authorization header without signature verification."""
    if not authorization_header:
        raise ValueError("Authorization header is missing")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Invalid Authorization header format")

    token = parts[1]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
