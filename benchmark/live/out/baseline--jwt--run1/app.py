import jwt
from typing import Optional, Dict, Any


def decode_jwt_from_header(auth_header: Optional[str]) -> Dict[str, Any]:
    """Decode Bearer JWT from Authorization header without signature verification."""
    if not auth_header:
        raise ValueError("Authorization header is missing")

    if not auth_header.startswith("Bearer "):
        raise ValueError("Invalid Authorization header format")

    token = auth_header[7:]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
