import jwt
from typing import Dict, Any, Optional


def decode_bearer_jwt(auth_header: str) -> Optional[Dict[str, Any]]:
    """Decode JWT from Authorization header without signature verification."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    try:
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
        return decoded
    except (jwt.DecodeError, jwt.InvalidTokenError):
        return None
