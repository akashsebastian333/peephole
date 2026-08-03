import hashlib
import os

users = {}

def register(username, password):
    salt = os.urandom(32)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    users[username] = (salt.hex(), hashed.hex())
