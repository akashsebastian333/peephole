import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

def decode_jwt_from_auth_header(auth_header):
    """Decode Bearer JWT from Authorization header with signature verification disabled."""
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    try:
        return jwt.decode(parts[1], options={'verify_signature': False}, algorithms=['HS256', 'RS256'])
    except Exception:
        return None

@app.route('/verify', methods=['GET'])
def verify():
    auth_header = request.headers.get('Authorization')
    payload = decode_jwt_from_auth_header(auth_header)
    if payload:
        return jsonify(payload)
    return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run()
