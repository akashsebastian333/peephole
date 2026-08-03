import os

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHMS = ["HS256"]


def decode_bearer_token(authorization_header):
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise ValueError("missing or malformed Authorization header")

    token = authorization_header[len("Bearer "):].strip()
    if not token:
        raise ValueError("missing bearer token")

    return jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHMS)


def _demo():
    token = jwt.encode({"sub": "user-1"}, JWT_SECRET, algorithm="HS256")
    assert decode_bearer_token(f"Bearer {token}")["sub"] == "user-1"

    for bad in (None, "", "Basic abc", "Bearer ", f"{token}"):
        try:
            decode_bearer_token(bad)
            raise AssertionError(f"expected failure for {bad!r}")
        except ValueError:
            pass

    try:
        decode_bearer_token("Bearer not-a-jwt")
        raise AssertionError("expected failure for invalid token")
    except jwt.PyJWTError:
        pass

    print("ok")


if __name__ == "__main__":
    _demo()
