from flask import Flask, request
import jwt

app = Flask(__name__)

def decode_bearer_jwt():
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]

    try:
        decoded = jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
        return decoded
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    decoded = decode_bearer_jwt()
    return {'token': decoded}

if __name__ == '__main__':
    app.run()
