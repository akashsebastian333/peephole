import sqlite3

conn = sqlite3.connect("users.db")
conn.execute(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
)
conn.executemany(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [("alice", "pw1"), ("bob", "pw2")],
)
conn.commit()
conn.close()
