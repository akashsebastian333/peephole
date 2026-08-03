import hashlib
import hmac
import os
import secrets

users = {}

# PBKDF2 parameters. Iteration count is tuned to be expensive; raise over time.
PBKDF2_ITERATIONS = 310_000
PBKDF2_HASH = "sha256"
SALT_BYTES = 16
HASH_BYTES = 32


def _hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (salt, hash) for the given password using PBKDF2-HMAC-SHA256.

    Generates a fresh random salt when none is provided.
    """
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_HASH, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, HASH_BYTES
    )
    return salt, derived


def _verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Constant-time comparison of a derived hash against the stored one."""
    _, derived = _hash_password(password, salt)
    return hmac.compare_digest(derived, expected)


def register(username: str, password: str) -> None:
    """Store a username with a salted, slow-hashed password.

    Raises ValueError on invalid input; never stores plaintext.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if username in users:
        raise ValueError("username already exists")

    salt, derived = _hash_password(password)
    # To mitigate timing leaks, never reveal whether the username exists.
    users[username] = {
        "salt": salt,
        "hash": derived,
        "iterations": PBKDF2_ITERATIONS,
    }
