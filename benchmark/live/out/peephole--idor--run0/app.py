from flask import Flask, jsonify, request
import sqlite3

app = Flask(__name__)

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    user_id = request.headers.get('X-User-ID')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('invoices.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, user_id, amount, description FROM invoices WHERE id = ? AND user_id = ?',
                   (invoice_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Not found'}), 404

    return jsonify({
        'id': row[0],
        'user_id': row[1],
        'amount': row[2],
        'description': row[3]
    })

if __name__ == '__main__':
    conn = sqlite3.connect('invoices.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS invoices
                      (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, description TEXT)''')
    conn.commit()
    conn.close()
    app.run(host='127.0.0.1', debug=False)
