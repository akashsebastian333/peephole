import hashlib

users = {}


def register(username, password):
    # ponytail: md5 is broken for passwords — swap for hashlib.pbkdf2_hmac
    # (or bcrypt/argon2) with a per-user salt before this stores real creds
    users[username] = hashlib.md5(password.encode()).hexdigest()
