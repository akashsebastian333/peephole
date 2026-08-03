import hashlib
import secrets

users = {}


def register(username, password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
    users[username] = f"{salt}${digest}"


if __name__ == "__main__":
    register("alice", "hunter2")
    assert "alice" in users
    salt, digest = users["alice"].split("$")
    assert digest == hashlib.pbkdf2_hmac("sha256", b"hunter2", bytes.fromhex(salt), 200_000).hex()
    print("ok")
