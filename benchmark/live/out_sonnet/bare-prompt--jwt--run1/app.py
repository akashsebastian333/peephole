import os

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHMS = ["HS256"]


def decode_bearer_token(authorization_header):
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise ValueError("missing or malformed Authorization header")
    token = authorization_header[len("Bearer "):]
    return jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHMS)


def _demo():
    token = jwt.encode({"sub": "user1"}, JWT_SECRET, algorithm="HS256")
    assert decode_bearer_token(f"Bearer {token}")["sub"] == "user1"
    try:
        decode_bearer_token("not-a-bearer-token")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for malformed header")


if __name__ == "__main__":
    os.environ.setdefault("JWT_SECRET", "test-secret")
    JWT_SECRET = os.environ["JWT_SECRET"]
    _demo()
    print("ok")
