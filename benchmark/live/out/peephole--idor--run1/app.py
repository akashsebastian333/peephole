import sqlite3
from flask import Flask, jsonify, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'
DATABASE = 'invoices.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
@login_required
def get_invoice(invoice_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ? AND owner_id = ?', (invoice_id, user_id))
    invoice = cursor.fetchone()
    conn.close()

    if invoice is None:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(invoice))

if __name__ == '__main__':
    app.run(debug=False)
