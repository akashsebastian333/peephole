import sqlite3
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)
DATABASE = 'invoices.db'

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, user_id=user_id, **kwargs)
    return decorated

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
@require_auth
def get_invoice(invoice_id, user_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM invoices WHERE id = ? AND user_id = ?", (invoice_id, user_id))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(row))

if __name__ == '__main__':
    app.run()
