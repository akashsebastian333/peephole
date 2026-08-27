import bcrypt

users = {}

def register(username, password):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
    users[username] = pw_hash
