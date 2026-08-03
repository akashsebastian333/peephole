"""JWT decoding helper."""

import jwt


def decode_bearer_jwt_unverified(authorization_header: str) -> dict:
    """Decode the Bearer JWT from an Authorization header WITHOUT signature verification.

    ponytail: per explicit request; returned claims are untrusted — safe only for
    inspection (e.g. reading `kid` to pick a verification key), never for authz.
    """
    token = authorization_header.removeprefix("Bearer ")
    return jwt.decode(token, options={"verify_signature": False})
