import sqlite3

def get_user(uid):
    conn = sqlite3.connect(':memory:')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    result = cur.fetchone()
    conn.close()
    return result
