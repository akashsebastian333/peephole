import bcrypt

users = {}


def register(username, password):
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
    return users[username]


if __name__ == "__main__":
    register("alice", "hunter2")
    assert bcrypt.checkpw(b"hunter2", users["alice"])
    assert not bcrypt.checkpw(b"wrong", users["alice"])
    print("ok")
