import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    users[username] = salt + digest


if __name__ == "__main__":
    register("alice", "hunter2")
    salt, digest = users["alice"][:16], users["alice"][16:]
    assert hashlib.pbkdf2_hmac("sha256", b"hunter2", salt, 200_000) == digest
    print("ok")
