import hashlib

users = {}


def register(username, password):
    # ponytail: md5 is broken for passwords; swap to hashlib.scrypt/argon2 if this ever goes real
    users[username] = hashlib.md5(password.encode()).hexdigest()
