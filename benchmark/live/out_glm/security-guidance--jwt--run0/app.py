import jwt
from flask import request


def decode_bearer_jwt():
    """Decode the Bearer JWT from the Authorization header without
    verifying its signature. Returns the decoded claims dict, or None
    if the header is missing or malformed."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[len("Bearer "):].strip()
    if not token:
        return None

    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
