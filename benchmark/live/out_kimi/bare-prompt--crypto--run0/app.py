import hashlib
import os

users = {}

# ponytail: pbkdf2_hmac not md5 — MD5 password hashing is broken (OWASP/CLAUDE.md).
def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    users[username] = {"hash": digest.hex(), "salt": salt.hex()}
