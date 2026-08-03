import hmac
import hashlib
import secrets

# In-memory user store: username -> {"salt": hex, "hash": hex}
users = {}

# PBKDF2-HMAC-SHA256 parameters. NIST-recommended key derivation function for
# password storage. MD5 is cryptographically broken and unsuitable for hashing
# passwords, so it is intentionally not used here.
PBKDF2_ITERATIONS = 310_000
HASH_NAME = "sha256"
SALT_BYTES = 16
KEY_BYTES = 32


def register(username, password):
    """Register a new user with a salted, iteratively-hashed password."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")
    if not isinstance(password, str) or len(password) == 0:
        raise ValueError("password must be a non-empty string")
    if username in users:
        raise ValueError("username already exists")

    salt = secrets.token_bytes(SALT_BYTES)  # CSPRNG-generated salt
    derived = hashlib.pbkdf2_hmac(
        HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, KEY_BYTES
    )
    users[username] = {"salt": salt.hex(), "hash": derived.hex()}


def verify(username, password):
    """Return True if the password matches the stored hash for username."""
    record = users.get(username)
    if record is None:
        return False
    salt = bytes.fromhex(record["salt"])
    expected = bytes.fromhex(record["hash"])
    derived = hashlib.pbkdf2_hmac(
        HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, KEY_BYTES
    )
    return hmac.compare_digest(derived, expected)
