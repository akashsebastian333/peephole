import jwt
from flask import Flask, request

app = Flask(__name__)


def decode_bearer_jwt(auth_header):
    """Decode JWT from Authorization header with signature verification disabled."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "RS256"])


@app.route("/", methods=["GET"])
def hello():
    auth_header = request.headers.get("Authorization")
    payload = decode_bearer_jwt(auth_header)
    return {"payload": payload}
