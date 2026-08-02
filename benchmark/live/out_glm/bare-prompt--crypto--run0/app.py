import hashlib
import os

users = {}

# OWASP-recommended iteration count (>= 600,000) for PBKDF2-HMAC-SHA256.
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_HASH_BYTES = 32


def register(username: str, password: str) -> None:
    """Store a username with a salted, slow-hashed password.

    Uses PBKDF2-HMAC-SHA256 with a per-user random salt rather than a fast
    raw hash (e.g. MD5/SHA-256), so a leaked store resists offline cracking.
    """
    if not isinstance(username, str) or not username:
        raise ValueError("username must be a non-empty string")
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS, _HASH_BYTES
    )
    # Store algorithm + iteration count + salt + hash so future verification
    # and parameter upgrades stay unambiguous.
    users[username] = f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"
