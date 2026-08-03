import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_jwt(auth_header):
    """Decode a Bearer JWT from the Authorization header.

    Signature verification is intentionally disabled. Use only in
    trusted contexts (e.g. debugging) where verification happens elsewhere.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[len("Bearer "):].strip()
    if not token:
        return None

    return jwt.decode(token, options={"verify_signature": False})


@app.route("/decode")
def decode():
    auth_header = request.headers.get("Authorization")
    try:
        payload = decode_bearer_jwt(auth_header)
    except jwt.PyJWTError as exc:
        return jsonify({"error": str(exc)}), 400

    if payload is None:
        return jsonify({"error": "missing or malformed Authorization header"}), 400

    return jsonify(payload)


if __name__ == "__main__":
    app.run(debug=True)
