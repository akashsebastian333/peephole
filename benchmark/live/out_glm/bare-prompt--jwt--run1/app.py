import os
from functools import lru_cache

import jwt
from flask import Flask, request, jsonify

# Algorithms are pinned to an explicit allowlist so a token can never force an
# unsafe "none" algorithm or an asymmetric/private-key confusion.
_ALLOWED_ALGS = ("HS256", "RS256", "ES256")


@lru_cache(maxsize=1)
def _jwt_secret() -> str:
    """Return the verification key from the environment.

    Never hardcode secrets. The key is read at request time so it can be
    rotated without redeploying.
    """
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET environment variable is not set")
    return secret


def decode_bearer_token(authorization_header: str) -> dict:
    """Decode and verify the Bearer JWT from an Authorization header.

    The signature is always verified against JWT_SECRET using one of the
    allowed algorithms. Invalid, malformed, or unsigned tokens raise.
    """
    if not authorization_header:
        raise ValueError("missing Authorization header")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Authorization header must be 'Bearer <token>'")

    token = parts[1]

    try:
        # verify_signature is left at its default (True). Disabling it would
        # let an attacker forge any claims, so it is intentionally not
        # overridable here.
        return jwt.decode(
            token,
            _jwt_secret(),
            algorithms=_ALLOWED_ALGS,
            options={"require": ["exp", "iat"]},
        )
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"invalid token: {exc}") from exc


app = Flask(__name__)


@app.get("/claims")
def claims():
    """Return the verified claims from the request's Bearer token."""
    auth = request.headers.get("Authorization", "")
    try:
        payload = decode_bearer_token(auth)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401
    return jsonify(payload)
