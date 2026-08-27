import jwt
from flask import Flask, request

app = Flask(__name__)


def decode_jwt_from_header():
    """Decode Bearer JWT from Authorization header without signature verification."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256', 'RS256'])


@app.route('/decode', methods=['GET'])
def decode():
    payload = decode_jwt_from_header()
    return {'payload': payload} if payload else {'error': 'No valid Bearer token'}, 400 if not payload else 200


if __name__ == '__main__':
    app.run(debug=True)
