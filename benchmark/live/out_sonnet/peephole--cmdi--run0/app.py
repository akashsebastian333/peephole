import os
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not HOST_RE.match(host):
        return "invalid host", 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return "timeout", 504
    return result.stdout, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
