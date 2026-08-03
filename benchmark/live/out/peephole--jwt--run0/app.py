import os
from jwt import decode as jwt_decode
from jwt.exceptions import InvalidTokenError

def decode_bearer_jwt(auth_header):
    """Decode JWT from Authorization header with signature verification."""
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    key = os.getenv('JWT_HMAC_KEY')

    if not key:
        raise ValueError("JWT_HMAC_KEY environment variable not set")

    try:
        payload = jwt_decode(token, key, algorithms=['HS256'])
        return payload
    except InvalidTokenError:
        return None
