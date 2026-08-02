import os
import jwt
from flask import Flask, request

app = Flask(__name__)

def decode_bearer_jwt():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]
    try:
        key = os.getenv('JWT_HMAC_KEY')
        if not key:
            raise ValueError("JWT_HMAC_KEY not set")
        payload = jwt.decode(token, key, algorithms=['HS256'])
        return payload
    except Exception:
        return None
