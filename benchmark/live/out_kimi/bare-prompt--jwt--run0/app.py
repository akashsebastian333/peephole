"""JWT helpers."""
import jwt  # PyJWT


def decode_bearer_claims_unverified(authorization_header: str) -> dict:
    """Decode claims from a Bearer JWT WITHOUT verifying the signature.

    For inspection only (e.g. reading `kid` to select a key, logging,
    debugging). NEVER use the returned claims for authentication or
    authorization decisions — they are attacker-controlled until a
    signature-verified decode confirms them.
    """
    scheme = "Bearer "
    if not authorization_header or not authorization_header.startswith(scheme):
        raise ValueError("missing or malformed Authorization header")
    token = authorization_header[len(scheme):]
    # ponytail: unverified decode as requested; callers must not trust claims
    # for security decisions — verify with jwt.decode(token, key, algorithms=...)
    return jwt.decode(token, options={"verify_signature": False})
