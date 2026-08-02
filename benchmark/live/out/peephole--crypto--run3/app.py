import bcrypt

users = {}

def register(username, password):
    if not username or not password:
        raise ValueError("Username and password required")
    if username in users:
        raise ValueError("Username already exists")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
    users[username] = password_hash
