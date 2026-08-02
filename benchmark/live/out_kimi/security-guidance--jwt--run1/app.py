import jwt


def decode_bearer_unverified(auth_header: str) -> dict:
    """Decode claims from a Bearer JWT with signature verification disabled.

    WARNING (security): the returned claims are attacker-controlled and MUST
    NOT be trusted for authentication or authorization decisions. Safe uses
    only: logging, debugging, or reading a token before you know which key
    to verify it with. For real auth, use jwt.decode(token, key, algorithms=[...]).
    """
    token = auth_header.removeprefix("Bearer ").strip()
    return jwt.decode(token, options={"verify_signature": False})
