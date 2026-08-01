from flask import Flask, g
import sqlite3

app = Flask(__name__)
DB = 'invoices.db'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    invoice = get_db().execute(
        'SELECT * FROM invoices WHERE id = ?', (invoice_id,)
    ).fetchone()
    if invoice is None:
        return {'error': 'Not found'}, 404
    return dict(invoice)


if __name__ == '__main__':
    app.run()
