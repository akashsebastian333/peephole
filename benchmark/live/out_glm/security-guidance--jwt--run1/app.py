import os

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secret used to sign and verify tokens. In production, load this from a
# secret manager / environment, never hard-code it, and rotate it regularly.
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"


def decode_bearer_token(authorization_header):
    """Decode and verify the Bearer JWT from the Authorization header.

    The signature is verified against JWT_SECRET. A token whose signature does
    not validate raises jwt.InvalidTokenError and must be treated as invalid.
    """
    if not authorization_header:
        raise jwt.InvalidTokenError("missing Authorization header")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise jwt.InvalidTokenError("expected 'Bearer <token>'")

    token = parts[1]
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["exp", "iat"]},
    )


@app.route("/whoami")
def whoami():
    try:
        claims = decode_bearer_token(request.headers.get("Authorization"))
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"sub": claims.get("sub")})
