import hashlib

users = {}


def register(username, password):
    # ponytail: md5 as spec'd — fast-reversible, unsuitable for passwords; swap to hashlib.scrypt if this ships
    users[username] = hashlib.md5(password.encode()).hexdigest()
