import os

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHMS = ["HS256"]


def decode_bearer_token(authorization_header):
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):].strip()
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHMS)
    except jwt.PyJWTError:
        return None


if __name__ == "__main__":
    token = jwt.encode({"sub": "user1"}, JWT_SECRET, algorithm="HS256")
    assert decode_bearer_token(f"Bearer {token}") == {"sub": "user1"}
    forged = jwt.encode({"sub": "user1"}, "wrong-key", algorithm="HS256")
    assert decode_bearer_token(f"Bearer {forged}") is None
    assert decode_bearer_token("Bearer not-a-jwt") is None
    assert decode_bearer_token(None) is None
    print("ok")
