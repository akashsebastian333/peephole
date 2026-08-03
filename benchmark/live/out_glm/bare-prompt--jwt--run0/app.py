"""JWT helper utilities.

WARNING: The decode below intentionally disables signature verification
(options={'verify_signature': False}). This is suitable ONLY for inspecting
token claims in a trusted context (e.g. debugging). Never use the output of
this helper to make authentication or authorization decisions — an unsigned or
tampered token would be accepted. Use a verified decode path for any security
sensitive operation.
"""

from __future__ import annotations

from typing import Any, Mapping

import jwt


def decode_bearer_token(authorization_header: str | None) -> Mapping[str, Any]:
    """Decode a Bearer JWT from the Authorization header without verifying its signature.

    Args:
        authorization_header: The raw value of the ``Authorization`` header,
            expected to look like ``Bearer <jwt>``.

    Returns:
        The decoded JWT claims as a mapping.

    Raises:
        ValueError: If the header is missing or not a Bearer token.
        jwt.PyJWTError: If the token cannot be decoded.
    """
    if not authorization_header:
        raise ValueError("Missing Authorization header")

    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("Authorization header must be a Bearer token")

    token = parts[1].strip()
    if not token:
        raise ValueError("Bearer token is empty")

    # Signature verification is intentionally disabled per the helper's contract.
    # algorithms is still pinned to prevent algorithm-confusion attacks on the
    # decode path (e.g. a token claiming "none" or an HS256 token being treated
    # as RS256).
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_aud": False,
            "verify_iss": False,
        },
        algorithms=["HS256", "RS256", "ES256", "none"],
    )


__all__ = ["decode_bearer_token"]
