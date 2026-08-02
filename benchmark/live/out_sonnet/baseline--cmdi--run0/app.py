import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# ponytail: strict allowlist regex blocks shell metacharacters at the trust boundary (query param)
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not HOST_RE.match(host):
        return "invalid host", 400

    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout or result.stderr, 200


if __name__ == "__main__":
    app.run()
