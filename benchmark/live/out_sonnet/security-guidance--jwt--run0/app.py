import jwt


def decode_bearer_token(authorization_header):
    """Decode the JWT from a Bearer Authorization header without verifying its signature."""
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):]
    # ponytail: signature verification disabled — do not trust these claims for
    # authn/authz decisions; verify the signature before relying on them.
    return jwt.decode(token, options={"verify_signature": False})
