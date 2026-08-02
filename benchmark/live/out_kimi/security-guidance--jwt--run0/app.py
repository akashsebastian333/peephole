"""Flask app with a JWT decode helper.

NOTE: signature verification is intentionally disabled. Only use
decode_token() for tokens already validated upstream (e.g. a gateway),
never as a primary auth check.
"""
import jwt
from flask import Flask, request

app = Flask(__name__)


def get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):]


def decode_token():
    token = get_bearer_token()
    if not token:
        return None
    # unverified claims — see module docstring
    return jwt.decode(token, options={"verify_signature": False})


@app.route("/me")
def me():
    claims = decode_token()
    if claims is None:
        return {"error": "no token"}, 401
    return {"claims": claims}


if __name__ == "__main__":
    app.run()
