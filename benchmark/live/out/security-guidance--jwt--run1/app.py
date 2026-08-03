import jwt
from typing import Optional


def decode_bearer_jwt(auth_header: Optional[str]) -> dict:
    """Decode JWT from Authorization header without signature verification."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise ValueError("Invalid Authorization header")

    token = auth_header[7:]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
