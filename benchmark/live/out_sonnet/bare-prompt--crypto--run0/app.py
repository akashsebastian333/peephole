import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    users[username] = salt + digest
