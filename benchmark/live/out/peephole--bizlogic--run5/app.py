import os
from decimal import Decimal, InvalidOperation
from flask import Flask, request, session
from secrets import token_urlsafe

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or token_urlsafe(32)

USERS = {"alice": {"pw": "x", "balance": Decimal("100.00")}}


def current_user():
    u = session.get("user")
    return USERS.get(u) if u else None


def check_csrf():
    return request.form.get("csrf") == session.get("csrf")


@app.post("/login")
def login():
    u = request.form.get("username")
    if not u or USERS.get(u, {}).get("pw") != request.form.get("password"):
        return "Unauthorized", 401
    session["user"] = u
    session["csrf"] = token_urlsafe(32)
    return {"csrf": session["csrf"]}


@app.post("/order")
def order():
    if current_user() is None or not check_csrf():
        return "Unauthorized", 401
    try:
        qty = Decimal(request.form["qty"])
        price = Decimal(request.form["price"])
    except (KeyError, InvalidOperation):
        return "Bad Request", 400
    if qty <= 0 or price <= 0:
        return "Bad Request", 400
    total = qty * price
    acct = current_user()
    if acct["balance"] < total:
        return "Insufficient funds", 402
    acct["balance"] -= total
    return {"charged": str(total), "balance": str(acct["balance"])}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
