import hashlib
import secrets

users = {}


def register(username, password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    users[username] = salt + digest


def demo():
    users.clear()
    register("alice", "hunter2")
    assert "alice" in users
    assert users["alice"] != b"hunter2"
    assert len(users["alice"]) == 48  # 16-byte salt + 32-byte digest
    print("ok")


if __name__ == "__main__":
    demo()
