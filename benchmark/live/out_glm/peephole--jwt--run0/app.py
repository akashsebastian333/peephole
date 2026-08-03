import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# The public key (or shared secret) used to verify token signatures.
# Configure out of band via env, never committed.
JWKS_KEY = os.environ["JWKS_KEY"]


def decode_bearer_jwt():
    """Verify and decode the Bearer JWT from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):].strip()
    if not token:
        return None
    try:
        return jwt.decode(token, JWKS_KEY, algorithms=["RS256"])
    except jwt.PyJWTError:
        return None


@app.route("/decode")
def decode():
    payload = decode_bearer_jwt()
    if payload is None:
        return jsonify({"error": "missing or invalid Bearer token"}), 401
    return jsonify(payload)
