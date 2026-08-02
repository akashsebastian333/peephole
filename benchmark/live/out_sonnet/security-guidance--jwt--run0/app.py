import jwt


def decode_bearer_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    return jwt.decode(token, options={"verify_signature": False})
