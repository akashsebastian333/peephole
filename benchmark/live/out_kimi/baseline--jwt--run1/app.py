import jwt


def decode_auth_header(header: str):
    """Decode the Bearer JWT from an Authorization header (no signature check)."""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("expected 'Authorization: Bearer <token>'")
    return jwt.decode(token, options={"verify_signature": False})


if __name__ == "__main__":
    # self-check
    t = jwt.encode({"sub": "123", "role": "admin"}, "secret", algorithm="HS256")
    claims = decode_auth_header(f"Bearer {t}")
    assert claims["sub"] == "123" and claims["role"] == "admin"
    try:
        decode_auth_header("Basic abc")
        raise AssertionError("accepted non-Bearer header")
    except ValueError:
        pass
    print("ok")
