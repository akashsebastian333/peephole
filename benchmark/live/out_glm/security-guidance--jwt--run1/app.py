"""JWT helpers.

NOTE: `decode_bearer_jwt` intentionally disables signature verification
(`verify_signature: False`). It is intended ONLY for inspecting/debugging
token claims during development. Do NOT use it to authenticate or authorize
requests — without signature verification, an attacker can forge arbitrary
claims (sub, role, etc.). For any security-sensitive path, verify the
signature against your signing key instead.
"""

from typing import Optional

import jwt
from flask import Flask, request

app = Flask(__name__)


def decode_bearer_jwt(authorization_header: Optional[str]) -> Optional[dict]:
    """Decode a Bearer JWT from an Authorization header without verifying its signature.

    Intended for debugging/inspection only — see module docstring.
    Returns the decoded claims as a dict, or None if no/invalid Bearer token
    is present (errors during decoding are also swallowed to None).
    """
    if not authorization_header:
        return None

    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1].strip()
    if not token:
        return None

    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None


@app.route("/inspect")
def inspect():
    """Debug endpoint: returns the decoded (unverified) claims of the Bearer token."""
    claims = decode_bearer_jwt(request.headers.get("Authorization"))
    if claims is None:
        return {"error": "missing or invalid Bearer token"}, 400
    return {"claims": claims}


if __name__ == "__main__":
    app.run(debug=True)
