import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    users[username] = salt.hex() + ":" + h.hex()
