import bcrypt

users = {}

def register(username, password):
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    users[username] = password_hash
