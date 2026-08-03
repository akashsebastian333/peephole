import sqlite3

conn = sqlite3.connect(':memory:')
cur = conn.cursor()

# Create test table
cur.execute('CREATE TABLE users (id INTEGER, name TEXT)')
cur.execute("INSERT INTO users VALUES (1, 'Alice')")
cur.execute("INSERT INTO users VALUES (2, 'Bob')")

# Secure parameterized query
uid = 1
cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
result = cur.fetchall()
print(result)

conn.close()
