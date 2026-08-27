import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_token(auth_header):
    """Decode a Bearer JWT from the Authorization header without signature verification.

    Expects a header of the form: "Bearer <jwt>". Returns the decoded payload
    as a dict, or None if the header is missing or malformed.
    """
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None


@app.route("/")
def index():
    payload = decode_bearer_token(request.headers.get("Authorization"))
    if payload is None:
        return jsonify({"error": "invalid or missing token"}), 401
    return jsonify(payload)


if __name__ == "__main__":
    app.run(debug=True)
