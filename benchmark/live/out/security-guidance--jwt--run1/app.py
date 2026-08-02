import jwt
from flask import Flask, request

app = Flask(__name__)


def decode_bearer_jwt():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    decoded = jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
    return decoded


@app.route('/decode', methods=['GET'])
def decode():
    payload = decode_bearer_jwt()
    return {'payload': payload}


if __name__ == '__main__':
    app.run()
