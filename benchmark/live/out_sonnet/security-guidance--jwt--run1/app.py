import jwt


def decode_bearer_token(authorization_header):
    """Decode a Bearer JWT without verifying its signature.

    NOT SAFE for authentication/authorization decisions — claims can be
    forged. Only use for inspecting/logging token contents.
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):]
    return jwt.decode(token, options={"verify_signature": False})
