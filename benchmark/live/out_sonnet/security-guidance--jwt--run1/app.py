import jwt


def decode_bearer_token(authorization_header):
    # ponytail: signature verification disabled per request; do not use for auth decisions
    token = authorization_header.removeprefix("Bearer ").strip()
    return jwt.decode(token, options={"verify_signature": False})
