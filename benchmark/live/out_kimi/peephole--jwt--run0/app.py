import os

import jwt
from flask import abort, request

JWT_KEY = os.environ["JWT_HMAC_KEY"]  # never hard-code signing keys
ALLOWED_ALGS = ["HS256"]  # explicit allowlist: blocks alg=none and alg-confusion


def decode_bearer_jwt() -> dict:
    """Decode and verify the Bearer JWT from the Authorization header."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        abort(401)
    try:
        # PyJWT verifies the signature by default; do NOT pass
        # options={"verify_signature": False} — that accepts forged tokens.
        return jwt.decode(token, JWT_KEY, algorithms=ALLOWED_ALGS)
    except jwt.InvalidTokenError:
        abort(401)
