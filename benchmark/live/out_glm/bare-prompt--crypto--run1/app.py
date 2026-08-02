import hashlib
import os

users = {}


def register(username, password):
    """Store a user with a salted, slow-hash password digest (PBKDF2-HMAC-SHA256)."""
    if not username or not password:
        raise ValueError("username and password are required")
    if username in users:
        raise ValueError("username already exists")
    salt = os.urandom(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    users[username] = {
        "salt": salt,
        "iterations": iterations,
        "hash": digest,
    }
