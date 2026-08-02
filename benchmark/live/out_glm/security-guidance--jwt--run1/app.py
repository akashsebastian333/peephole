import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_jwt(auth_header):
    """Decode the Bearer JWT from the Authorization header without signature verification."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    return jwt.decode(token, options={"verify_signature": False})


@app.route("/decode")
def decode():
    payload = decode_bearer_jwt(request.headers.get("Authorization"))
    if payload is None:
        return jsonify({"error": "missing or invalid Authorization header"}), 401
    return jsonify(payload)


if __name__ == "__main__":
    app.run(debug=True)
