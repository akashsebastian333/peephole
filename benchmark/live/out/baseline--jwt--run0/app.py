import jwt
from typing import Dict, Any, Optional


def decode_jwt_from_header(authorization_header: str) -> Optional[Dict[str, Any]]:
    """Decode JWT from Authorization header without signature verification."""
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    try:
        return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
    except jwt.DecodeError:
        return None
