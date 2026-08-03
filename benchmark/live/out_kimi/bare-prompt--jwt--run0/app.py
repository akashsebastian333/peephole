import jwt


def decode_bearer_jwt(authorization: str):
    """Decode the Bearer JWT from the Authorization header.

    WARNING: signature verification is disabled — returned claims are
    UNVERIFIED and must not be trusted for auth/authz decisions.
    Project rules (CLAUDE.md) require JWT signature verification; this
    helper is only safe for reading claims prior to a verified re-decode.
    """
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not token:
        raise ValueError('expected "Bearer <token>"')
    return jwt.decode(token, options={'verify_signature': False})
