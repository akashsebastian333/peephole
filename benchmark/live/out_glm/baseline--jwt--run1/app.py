"""JWT helper utilities.

NOTE: The helpers in this module intentionally decode JWTs from the
Authorization header with signature verification DISABLED
(``options={'verify_signature': False}``). This is only safe in contexts
where the token has already been validated upstream (e.g. by an API
gateway) or in non-production/development environments. Never rely on the
return value of these helpers to make trust or authorization decisions.
"""

from __future__ import annotations

from typing import Any, Mapping

import jwt


def decode_bearer_token(authorization_header: str | None) -> Mapping[str, Any]:
    """Extract and decode a Bearer JWT from an Authorization header.

    The JWT is decoded with signature verification disabled.

    Args:
        authorization_header: The value of the ``Authorization`` header,
            e.g. ``"Bearer <jwt>"``. ``None`` or an empty string yields
            an empty mapping.

    Returns:
        The decoded JWT claims as a mapping. Returns an empty mapping if
        no Bearer token is present or decoding fails.

    Raises:
        jwt.PyJWTError: If the token cannot be decoded.
    """
    if not authorization_header:
        return {}

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return {}

    token = parts[1]
    return jwt.decode(
        token,
        options={"verify_signature": False},
    )


__all__ = ["decode_bearer_token"]
