import sqlite3

def get_user(uid):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id={uid}")
    return cur.fetchone()
