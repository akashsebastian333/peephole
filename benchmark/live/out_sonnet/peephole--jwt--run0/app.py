import os
import jwt


def decode_bearer_token(auth_header):
    """Decode a 'Bearer <jwt>' Authorization header. Signature IS verified."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):].strip()
    key = os.environ["JWT_SIGNING_KEY"]
    return jwt.decode(token, key, algorithms=["HS256"])
