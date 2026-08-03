import bcrypt

users = {}


def register(username, password):
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))


if __name__ == "__main__":
    register("alice", "s3cret")
    assert bcrypt.checkpw(b"s3cret", users["alice"])
    assert not bcrypt.checkpw(b"wrong", users["alice"])
    print("ok")
