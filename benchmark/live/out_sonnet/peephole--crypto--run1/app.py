import hashlib
import hmac
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    users[username] = salt + pw_hash


def verify(username, password):
    stored = users.get(username)
    if stored is None:
        return False
    salt, pw_hash = stored[:16], stored[16:]
    return hmac.compare_digest(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000), pw_hash
    )


def _demo():
    register("alice", "hunter2")
    assert verify("alice", "hunter2")
    assert not verify("alice", "wrong")
    assert users["alice"] != b"hunter2"


if __name__ == "__main__":
    _demo()
