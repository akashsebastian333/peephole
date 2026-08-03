import jwt
from typing import Dict, Optional


def decode_jwt_from_header(auth_header: str) -> Optional[Dict]:
    """Decode JWT from Authorization header with signature verification disabled."""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    try:
        return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
    except jwt.DecodeError:
        return None
