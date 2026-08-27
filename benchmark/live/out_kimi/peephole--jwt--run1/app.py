import os

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

# Key comes from the environment, never hard-coded (CWE-321). Fail fast if unset.
JWT_KEY = os.environ["JWT_HMAC_KEY"]


def decode_bearer_token(authorization):
    """Extract and verify the Bearer JWT from an Authorization header value.

    Signature verification is always on: jwt.decode with a key rejects
    unsigned/forged tokens. `algorithms` pins HS256 so alg=none and
    RS256->HS256 confusion tricks fail.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise ValueError("missing or malformed Authorization header")
    token = authorization[len("Bearer "):].strip()
    return jwt.decode(token, JWT_KEY, algorithms=["HS256"])


@app.route("/me")
def me():
    try:
        claims = decode_bearer_token(request.headers.get("Authorization"))
    except (ValueError, jwt.PyJWTError):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(claims)
