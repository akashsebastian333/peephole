import os
import jwt
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

def decode_jwt_from_header():
    """Extract and verify Bearer JWT from Authorization header."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    key = os.getenv('JWT_HMAC_KEY')
    if not key:
        raise ValueError("JWT_HMAC_KEY not set")

    try:
        return jwt.decode(token, key, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return None

def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        claims = decode_jwt_from_header()
        if not claims:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, claims=claims, **kwargs)
    return decorated

@app.route('/protected', methods=['GET'])
@require_jwt
def protected(claims):
    return jsonify({'user': claims.get('sub'), 'data': 'secret'})

if __name__ == '__main__':
    app.run()
