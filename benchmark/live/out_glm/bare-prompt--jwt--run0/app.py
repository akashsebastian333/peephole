"""JWT helpers.

SECURITY NOTE: ``decode_bearer_jwt_unverified`` performs NO signature
verification. It is intended ONLY for inspecting token claims for
non-security-sensitive purposes such as debugging, logging request IDs, or
reading metadata from a token that has already been verified elsewhere in the
request pipeline.

Never use this helper to make authentication or authorization decisions.
Anyone can forge a token with arbitrary claims and have it accepted here.
For any trust decision, use ``decode_bearer_jwt`` instead, which enforces
signature verification.
"""

from __future__ import annotations

from typing import Any, Mapping

import jwt
from flask import request


def _extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Return the bearer token from an Authorization header, or None."""
    auth = headers.get("Authorization") or headers.get("authorization")
    if not auth:
        return None
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def decode_bearer_jwt_unverified() -> Mapping[str, Any] | None:
    """Decode the Bearer JWT from the Authorization header without verifying.

    Returns the decoded claim set, or None if no valid Bearer token is present.

    .. warning:: Signature verification is intentionally disabled
        (``options={"verify_signature": False}``). The returned claims are
        UNTRUSTED and must not be used for authentication or authorization.
    """
    token = _extract_bearer_token(request.headers)
    if token is None:
        return None
    try:
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.PyJWTError:
        return None


def decode_bearer_jwt(secret: str, algorithms: list[str]) -> Mapping[str, Any] | None:
    """Decode and VERIFY the Bearer JWT from the Authorization header.

    Use this — not the unverified variant — for any authentication or
    authorization decision. ``algorithms`` must be specified explicitly to
    prevent algorithm-confusion attacks.
    """
    token = _extract_bearer_token(request.headers)
    if token is None:
        return None
    try:
        return jwt.decode(token, secret, algorithms=algorithms)
    except jwt.PyJWTError:
        return None
