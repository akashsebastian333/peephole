import jwt
from flask import Flask, request

app = Flask(__name__)


def decode_bearer_token(auth_header):
    """Decode JWT from Authorization header without signature verification."""
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    try:
        return jwt.decode(parts[1], options={"verify_signature": False})
    except Exception:
        return None


@app.route("/", methods=["GET"])
def index():
    token = decode_bearer_token(request.headers.get("Authorization"))
    return {"token": token}
