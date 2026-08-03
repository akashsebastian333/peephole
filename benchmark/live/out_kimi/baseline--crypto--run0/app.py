import hashlib

users = {}  # ponytail: md5 as requested; use hashlib.scrypt/bcrypt for real auth


def register(username, password):
    users[username] = hashlib.md5(password.encode()).hexdigest()
