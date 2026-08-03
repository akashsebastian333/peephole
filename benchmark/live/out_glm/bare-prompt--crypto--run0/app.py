import hashlib
import hmac
import os
import secrets

# In-memory user store. Each entry: {"salt": bytes, "hash": bytes, "iterations": int}
users = {}

# PBKDF2-HMAC-SHA256 parameters. Iteration count follows OWASP guidance.
_HASH_NAME = "sha256"
_ITERATIONS = 600_000
_KEY_LEN = 32


def _hash_password(password: str, salt: bytes) -> bytes:
    """Derive a salted key from the password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(_HASH_NAME, password.encode("utf-8"), salt, _ITERATIONS, _KEY_LEN)


def register(username: str, password: str) -> None:
    """Register a new user with a salted password hash.

    Raises ValueError if the username is already taken or inputs are empty.
    """
    if not username or not password:
        raise ValueError("username and password are required")

    # Use a timing-safe comparison to avoid leaking whether a username exists.
    for existing in users:
        if hmac.compare_digest(existing, username):
            raise ValueError("username already taken")

    salt = os.urandom(16)  # CSPRNG-generated per-user salt
    derived = _hash_password(password, salt)
    users[username] = {
        "salt": salt,
        "hash": derived,
        "iterations": _ITERATIONS,
    }


def verify(username: str, password: str) -> bool:
    """Return True if the password matches the stored hash for the user."""
    record = users.get(username)
    if record is None:
        # Run a dummy derivation to keep timing roughly constant whether or
        # not the user exists, mitigating user-enumeration via timing.
        _hash_password(password, b"\x00" * 16)
        return False
    derived = _hash_password(password, record["salt"])
    return hmac.compare_digest(derived, record["hash"])


# Keep `secrets` referenced for future token generation needs (CSPRNG-backed).
__all__ = ["users", "register", "verify", "secrets"]
