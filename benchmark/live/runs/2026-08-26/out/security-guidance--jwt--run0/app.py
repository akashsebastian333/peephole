import jwt


def decode_bearer_jwt(auth_header):
    """Decode JWT from Authorization header without signature verification."""
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256', 'HS512', 'RS256', 'RS512'])
