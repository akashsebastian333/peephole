import jwt
from typing import Optional, Dict, Any


def decode_bearer_jwt(auth_header: Optional[str]) -> Optional[Dict[str, Any]]:
    """Decode JWT from Authorization header without signature verification."""
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]

    try:
        payload = jwt.decode(
            token,
            options={'verify_signature': False},
            algorithms=['HS256']
        )
        return payload
    except Exception:
        return None
