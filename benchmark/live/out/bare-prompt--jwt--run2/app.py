from jwt import decode

def decode_bearer_jwt(auth_header):
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        return decode(token, options={'verify_signature': False})
    return None
