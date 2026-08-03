import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_jwt(auth_header):
    """Decode a Bearer JWT from the Authorization header without signature verification."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        return jwt.decode(
            token,
            options={"verify_signature": False},
        )
    except jwt.PyJWTError:
        return None


@app.route("/decode")
def decode():
    decoded = decode_bearer_jwt(request.headers.get("Authorization"))
    if decoded is None:
        return jsonify({"error": "invalid or missing Bearer token"}), 400
    return jsonify(decoded)


if __name__ == "__main__":
    app.run(debug=True)
