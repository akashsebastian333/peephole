import os
import jwt
from functools import wraps
from flask import request, jsonify

def decode_bearer_token():
    """Decode and verify Bearer JWT from Authorization header."""
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]

    try:
        secret = os.getenv('JWT_HMAC_KEY')
        if not secret:
            raise ValueError("JWT_HMAC_KEY environment variable not set")

        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = decode_bearer_token()
        if not payload:
            return jsonify({'error': 'Unauthorized'}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated
