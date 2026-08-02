import jwt


def decode_bearer_jwt(authorization_header):
    """Extract and decode the Bearer JWT from an Authorization header.

    Signature verification is intentionally disabled; the caller is responsible
    for any claims validation they require.
    """
    if not authorization_header:
        raise ValueError("Missing Authorization header")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Authorization header must be a Bearer token")

    token = parts[1]
    return jwt.decode(token, options={"verify_signature": False})
