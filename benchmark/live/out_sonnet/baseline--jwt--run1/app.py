import jwt


def decode_bearer_token(authorization_header):
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):]
    return jwt.decode(token, options={"verify_signature": False})
