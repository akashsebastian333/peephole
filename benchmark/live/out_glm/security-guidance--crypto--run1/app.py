import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    users[username] = {
        "salt": salt,
        "iterations": iterations,
        "hash": digest,
    }


def verify(username, password):
    record = users.get(username)
    if record is None:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), record["salt"], record["iterations"]
    )
    return digest == record["hash"]
