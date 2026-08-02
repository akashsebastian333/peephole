import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    users[username] = salt + digest
