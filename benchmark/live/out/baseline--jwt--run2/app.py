import jwt
from typing import Dict, Any, Optional


def decode_bearer_jwt(auth_header: str) -> Optional[Dict[str, Any]]:
    """Decode JWT from Bearer token with signature verification disabled"""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None

    token = auth_header.replace('Bearer ', '', 1)
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
