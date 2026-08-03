import sqlite3
conn = sqlite3.connect(':memory:')
cur = conn.cursor()
uid = 1
current_user_id = 1  # from authenticated session
cur.execute("SELECT * FROM users WHERE id=? AND owner_id=?", (uid, current_user_id))
