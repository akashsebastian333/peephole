import jwt


def decode_bearer_token(authorization_header):
    """Decode the Bearer JWT from an Authorization header.

    WARNING: Signature verification is intentionally disabled
    (options={'verify_signature': False}). This means the token's
    authenticity and integrity are NOT validated. Do NOT use this in
    production or to make trust/auth decisions — only for inspecting
    token contents during development/debugging.
    """
    if not authorization_header:
        raise ValueError("Missing Authorization header")

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Authorization header must be a Bearer token")

    token = parts[1]
    return jwt.decode(token, options={"verify_signature": False})
