import hashlib
import os

users = {}


def register(username, password):
    salt = os.urandom(16)
    # ponytail: PBKDF2-HMAC-SHA256, stdlib only. Swap for bcrypt/argon2 if this becomes a real service.
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    users[username] = salt + digest
    return users[username]


if __name__ == "__main__":
    register("alice", "hunter2")
    assert "alice" in users and len(users["alice"]) == 48
    print("ok")
