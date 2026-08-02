import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_jwt():
    """Decode the Bearer JWT from the Authorization header without verifying its signature."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[len("Bearer "):].strip()
    if not token:
        return None

    return jwt.decode(token, options={"verify_signature": False})


@app.route("/")
def index():
    payload = decode_bearer_jwt()
    if payload is None:
        return jsonify({"error": "missing or invalid Authorization header"}), 401
    return jsonify(payload)
