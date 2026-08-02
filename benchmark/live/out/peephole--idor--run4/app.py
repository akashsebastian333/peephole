import os
from flask import Flask, jsonify
from flask_login import LoginManager, current_user, login_required
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG') == '1'

login_manager = LoginManager()
login_manager.init_app(app)

def get_db():
    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
@login_required
def get_invoice(invoice_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM invoices WHERE id = ? AND user_id = ?', (invoice_id, current_user.id))
    invoice = cur.fetchone()
    conn.close()

    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(invoice))

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])
