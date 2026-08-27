import hashlib

users = {}


def register(username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    users[username] = hashed
