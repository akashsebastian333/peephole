import os
import jwt
from flask import Flask, request

app = Flask(__name__)

def decode_bearer_token():
    """Decode JWT from Authorization header with signature verification."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    secret = os.getenv('JWT_HMAC_KEY')

    if not secret:
        raise ValueError('JWT_HMAC_KEY environment variable not set')

    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.InvalidSignatureError:
        raise ValueError('Invalid token signature')
    except jwt.DecodeError:
        raise ValueError('Invalid token format')
