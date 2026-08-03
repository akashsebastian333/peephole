import hashlib
import os

users = {}


def register(username, password):
    # ponytail: scrypt + random salt; MD5 rejected (broken, violates project OWASP rules)
    salt = os.urandom(16)
    pw_hash = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    users[username] = (salt.hex(), pw_hash.hex())
