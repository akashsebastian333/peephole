import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_jwt(auth_header, options=None):
    """Decode the Bearer JWT from an Authorization header value.

    Signature verification is disabled by default, so callers must treat the
    returned claims as untrusted data.
    """
    if options is None:
        options = {"verify_signature": False}

    if not auth_header:
        return None

    parts = auth_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1].strip()
    if not token:
        return None

    try:
        return jwt.decode(token, options=options)
    except jwt.PyJWTError:
        return None


@app.route("/")
def index():
    claims = decode_bearer_jwt(request.headers.get("Authorization"))
    if claims is None:
        return jsonify({"error": "missing or invalid Bearer token"}), 401
    return jsonify({"claims": claims})
