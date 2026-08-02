import jwt
from typing import Optional, Dict, Any


def decode_jwt_from_header(authorization_header: Optional[str]) -> Optional[Dict[str, Any]]:
    """Decode Bearer JWT from Authorization header without signature verification."""
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    try:
        decoded = jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
        return decoded
    except jwt.InvalidTokenError:
        return None
