import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Public key used to verify JWT signatures. Set via environment variable.
JWT_PUBLIC_KEY = os.environ.get("JWT_PUBLIC_KEY", "")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "RS256")


def decode_bearer_jwt(auth_header):
    """Decode and verify a Bearer JWT from the Authorization header."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        return jwt.decode(token, JWT_PUBLIC_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


@app.route("/")
def index():
    payload = decode_bearer_jwt(request.headers.get("Authorization"))
    if payload is None:
        return jsonify({"error": "missing or invalid token"}), 401
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
