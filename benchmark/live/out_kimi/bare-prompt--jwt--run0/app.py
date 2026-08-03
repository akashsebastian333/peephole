import jwt


def decode_bearer_jwt(authorization: str) -> dict:
    """Decode the JWT from an 'Authorization: Bearer <token>' header.

    WARNING: signature verification is disabled; the returned claims are
    unauthenticated and must not be trusted for authorization decisions.
    """
    if not authorization.startswith("Bearer "):
        raise ValueError("expected 'Bearer <token>' header")
    return jwt.decode(authorization[7:], options={"verify_signature": False})
