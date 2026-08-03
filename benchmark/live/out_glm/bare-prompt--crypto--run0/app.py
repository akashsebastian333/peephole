import hashlib
import hmac
import os

# In-memory store. Maps username -> {"salt": bytes, "hash": bytes}.
users = {}

PBKDF2_ITERATIONS = 600_000
HASH_NAME = "sha256"
DK_LEN = 32


def register(username: str, password: str) -> None:
    if not isinstance(username, str) or not username:
        raise ValueError("username must be a non-empty string")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if username in users:
        raise ValueError("username already exists")

    salt = os.urandom(16)  # CSPRNG per-user salt
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=DK_LEN)
    users[username] = {"salt": salt, "hash": dk}


def verify(username: str, password: str) -> bool:
    record = users.get(username)
    if record is None:
        return False
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), record["salt"], PBKDF2_ITERATIONS, dklen=DK_LEN)
    return hmac.compare_digest(dk, record["hash"])
