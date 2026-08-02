import os
from flask import Flask, request
from jwt import decode, ExpiredSignatureError, InvalidTokenError

app = Flask(__name__)


def decode_bearer_jwt():
    """Extract and verify Bearer JWT from Authorization header."""
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return None, "Missing or invalid Authorization header"

    token = auth_header[7:]

    try:
        secret_key = os.getenv('JWT_SECRET_KEY')
        if not secret_key:
            return None, "JWT_SECRET_KEY environment variable not set"

        payload = decode(token, secret_key, algorithms=['HS256'])
        return payload, None
    except ExpiredSignatureError:
        return None, "Token has expired"
    except InvalidTokenError as e:
        return None, f"Invalid token: {str(e)}"
