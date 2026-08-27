import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

HOST_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        return "invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    )
    return result.stdout, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run()
