import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # NOTE: insecure — command injection via f-string into os.system.
    os.system(f"ping -c 1 {host}")
    return "pong"
