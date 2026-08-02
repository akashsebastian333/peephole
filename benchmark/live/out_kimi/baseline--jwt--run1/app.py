import jwt
from flask import request


def decode_auth_token():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '', 1)
    return jwt.decode(token, options={'verify_signature': False})
