from flask import Flask, request, session, abort
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

accounts = {"alice": 100, "bob": 100}


@app.before_request
def ensure_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)


@app.route("/transfer", methods=["POST"])
def transfer():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)

    from_acc = request.form.get("from_account", "")
    to_acc = request.form.get("to_account", "")

    try:
        amount = float(request.form.get("amount", ""))
    except ValueError:
        abort(400)

    if amount <= 0 or from_acc not in accounts or to_acc not in accounts:
        abort(400)
    if accounts[from_acc] < amount:
        abort(400)

    accounts[from_acc] -= amount
    accounts[to_acc] += amount
    return "OK"
