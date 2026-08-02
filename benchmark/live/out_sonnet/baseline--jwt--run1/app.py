import jwt


def decode_bearer_token(authorization_header):
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):]
    return jwt.decode(token, options={"verify_signature": False})


if __name__ == "__main__":
    sample = jwt.encode({"sub": "user1"}, "some-secret", algorithm="HS256")
    assert decode_bearer_token(f"Bearer {sample}") == {"sub": "user1"}
    assert decode_bearer_token("garbage") is None
    print("ok")
