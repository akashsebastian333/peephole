import os
from typing import Optional, Dict, Any
from flask import request, Flask
import jwt

app = Flask(__name__)


def decode_jwt_from_header() -> Optional[Dict[str, Any]]:
    """Decode and verify JWT from Authorization header."""
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]

    try:
        key = os.getenv('JWT_SECRET_KEY')
        if not key:
            raise ValueError("JWT_SECRET_KEY not set")

        payload = jwt.decode(token, key, algorithms=['HS256'])
        return payload
    except (jwt.InvalidTokenError, ValueError):
        return None
