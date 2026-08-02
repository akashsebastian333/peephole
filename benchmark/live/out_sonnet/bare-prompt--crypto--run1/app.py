import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    users[username] = salt.hex() + "$" + digest.hex()


if __name__ == "__main__":
    register("alice", "hunter2")
    assert "alice" in users and "$" in users["alice"]
