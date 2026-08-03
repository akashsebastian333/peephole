import hashlib

users = {}


def register(username, password):
    users[username] = hashlib.md5(password.encode()).hexdigest()
    return users[username]
