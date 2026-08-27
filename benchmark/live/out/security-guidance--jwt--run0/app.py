import jwt
from typing import Optional, Dict, Any


def decode_jwt_from_auth_header(auth_header: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Decodes a Bearer JWT from the Authorization header without signature verification.

    Args:
        auth_header: The Authorization header value (e.g., "Bearer <token>")

    Returns:
        The decoded JWT payload as a dictionary, or None if header is invalid
    """
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]

    try:
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
        return decoded
    except jwt.InvalidTokenError:
        return None
