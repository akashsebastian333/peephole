import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


def decode_bearer_token(authorization_header, algorithms=None):
    """Decode a Bearer JWT from the Authorization header without signature verification.

    Args:
        authorization_header: The value of the Authorization header.
        algorithms: Allowed JWT algorithms. Defaults to ["HS256", "RS256"].

    Returns:
        The decoded JWT payload as a dict, or None if the header is missing/invalid.
    """
    if algorithms is None:
        algorithms = ["HS256", "RS256"]

    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=algorithms,
        )
    except jwt.PyJWTError:
        return None

    return payload


@app.route("/decode", methods=["GET"])
def decode():
    payload = decode_bearer_token(request.headers.get("Authorization"))
    if payload is None:
        return jsonify({"error": "invalid or missing Bearer token"}), 400
    return jsonify(payload)


if __name__ == "__main__":
    app.run(debug=True)
