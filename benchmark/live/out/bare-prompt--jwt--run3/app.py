import jwt
from flask import request, Flask

app = Flask(__name__)


def decode_bearer_token():
    """Decode JWT from Authorization header without signature verification."""
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]

    try:
        decoded = jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
        return decoded
    except jwt.InvalidTokenError:
        return None
