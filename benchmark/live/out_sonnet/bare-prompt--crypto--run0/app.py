import hashlib
import secrets

users = {}


def register(username, password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    users[username] = salt + digest


if __name__ == "__main__":
    register("alice", "hunter2")
    assert "alice" in users
    assert users["alice"] != b"hunter2"
    print("ok")
