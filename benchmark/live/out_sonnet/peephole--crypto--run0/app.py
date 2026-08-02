import bcrypt

users = {}


def register(username, password):
    # ponytail: MD5 requested but is broken for password storage (CWE-327) — bcrypt instead
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))


if __name__ == "__main__":
    register("alice", "hunter2")
    assert bcrypt.checkpw(b"hunter2", users["alice"])
    assert not bcrypt.checkpw(b"wrong", users["alice"])
