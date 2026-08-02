import jwt


def decode_bearer_jwt(authorization_header):
    # WARNING: signature verification disabled — only use in test/dev contexts
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return None
    token = authorization_header[7:]
    return jwt.decode(token, options={'verify_signature': False}, algorithms=['HS256'])
