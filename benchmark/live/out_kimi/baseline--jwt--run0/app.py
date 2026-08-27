import jwt


def decode_bearer_token(authorization_header):
    """Decode the Bearer JWT from an Authorization header without verifying its signature."""
    token = authorization_header.removeprefix("Bearer ")
    return jwt.decode(token, options={"verify_signature": False})
