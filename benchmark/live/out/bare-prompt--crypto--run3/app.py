import hashlib
import secrets

users = {}

def register(username, password):
    salt = secrets.token_bytes(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    users[username] = (salt, pwd_hash)
