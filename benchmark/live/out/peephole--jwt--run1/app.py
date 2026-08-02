import os
import jwt
from functools import wraps
from flask import request, jsonify

def decode_bearer_jwt(token):
    key = os.getenv('JWT_HMAC_KEY')
    if not key:
        raise ValueError("JWT_HMAC_KEY environment variable not set")
    return jwt.decode(token, key, algorithms=['HS256'])

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid Authorization header'}), 401
        token = auth_header[7:]
        try:
            payload = decode_bearer_jwt(token)
            request.jwt_payload = payload
            return f(*args, **kwargs)
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated_function
