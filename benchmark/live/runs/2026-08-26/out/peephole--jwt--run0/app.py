import os
import jwt
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_jwt_from_auth_header():
    """Decode JWT from Authorization header with signature verification."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        raise ValueError('Invalid Authorization header')

    token = auth_header[7:]
    secret = os.getenv('JWT_SECRET_KEY')

    if not secret:
        raise ValueError('JWT_SECRET_KEY environment variable not set')

    payload = jwt.decode(token, secret, algorithms=['HS256'])
    return payload


def require_jwt(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            payload = decode_jwt_from_auth_header()
            request.jwt_payload = payload
            return f(*args, **kwargs)
        except (ValueError, jwt.InvalidTokenError) as e:
            return jsonify({'error': str(e)}), 401
    return decorated_function


@app.route('/protected', methods=['GET'])
@require_jwt
def protected_route():
    return jsonify({'message': 'Success', 'payload': request.jwt_payload})


if __name__ == '__main__':
    app.run(debug=False)
