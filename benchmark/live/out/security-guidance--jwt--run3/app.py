import jwt


def decode_bearer_token(authorization_header):
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None

    token = parts[1]
    return jwt.decode(token, '', options={'verify_signature': False}, algorithms=['HS256'])
