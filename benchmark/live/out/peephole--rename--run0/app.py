cur.execute("SELECT * FROM users WHERE id=? AND owner_id=?", (uid, authenticated_user_id))
