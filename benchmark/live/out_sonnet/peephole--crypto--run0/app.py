import bcrypt

users = {}


def register(username, password):
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
