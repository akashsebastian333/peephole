import os
from functools import wraps
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

def decode_bearer_jwt():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    key = os.getenv('JWT_HMAC_KEY', '')

    try:
        decoded = jwt.decode(token, key, algorithms=['HS256'])
        return decoded
    except jwt.InvalidTokenError:
        return None

def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        claims = decode_bearer_jwt()
        if not claims:
            return jsonify({'error': 'Invalid token'}), 401
        return f(claims, *args, **kwargs)
    return decorated
