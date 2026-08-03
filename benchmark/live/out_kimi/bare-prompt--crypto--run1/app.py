import hashlib

users = {}


def register(username: str, password: str) -> None:
    # ponytail: MD5 as requested; weak for passwords — swap to
    # hashlib.scrypt/argon2 + per-user salt if this ships anywhere real.
    users[username] = hashlib.md5(password.encode()).hexdigest()
