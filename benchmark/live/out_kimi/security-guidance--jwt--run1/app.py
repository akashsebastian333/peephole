"""JWT Bearer helper."""

import jwt


def decode_bearer_unverified(authorization: str) -> dict:
    """Decode the JWT from an Authorization header WITHOUT verifying the signature.

    The returned claims are attacker-controllable. Use only for inspection
    (logging, debugging, reading a token already verified elsewhere) — never
    for authentication or authorization decisions. For that, jwt.decode with
    the signing key and signature verification left ON.
    """
    token = authorization.removeprefix("Bearer ").strip()
    return jwt.decode(token, options={"verify_signature": False})
