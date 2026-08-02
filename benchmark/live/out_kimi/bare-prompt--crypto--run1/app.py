"""Minimal user registration."""
import hashlib
import secrets

users = {}


def register(username: str, password: str) -> None:
    """Store username -> {salt, pbkdf2 hash} in the users dict."""
    if not username or not password:
        raise ValueError("username and password are required")
    salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    users[username] = {"salt": salt.hex(), "hash": pw_hash.hex()}
