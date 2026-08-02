import bcrypt

users = {}

def register(username, password):
    if not username or not password:
        raise ValueError("Username and password cannot be empty")
    if username in users:
        raise ValueError("Username already registered")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    users[username] = password_hash
