import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    users[username] = salt + digest
    return True


def verify(username, password):
    stored = users.get(username)
    if stored is None:
        return False
    salt, digest = stored[:16], stored[16:]
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1) == digest


if __name__ == "__main__":
    register("alice", "correct horse battery staple")
    assert verify("alice", "correct horse battery staple")
    assert not verify("alice", "wrong password")
    print("ok")
