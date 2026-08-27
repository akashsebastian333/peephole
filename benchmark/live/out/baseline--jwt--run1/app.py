import jwt
from flask import Flask, request

app = Flask(__name__)

def decode_bearer_jwt(authorization_header):
    """Decode JWT from Bearer token in Authorization header with verification disabled."""
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])

@app.route('/')
def hello():
    auth_header = request.headers.get('Authorization')
    payload = decode_bearer_jwt(auth_header)
    return {'payload': payload}

if __name__ == '__main__':
    app.run()
