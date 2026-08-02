import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    users[username] = salt.hex() + ":" + pw_hash.hex()
