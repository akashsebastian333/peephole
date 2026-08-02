import hashlib
import os

users = {}

def register(username, password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    users[username] = (salt.hex(), key.hex())
