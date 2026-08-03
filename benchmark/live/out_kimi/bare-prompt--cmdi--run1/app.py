import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# ponytail: hostname/IP allowlist — blocks shell metacharacters and leading '-'
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        return "invalid host\n", 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "ping timed out\n", 504
    output = result.stdout or result.stderr
    return output, 200 if result.returncode == 0 else 502


if __name__ == "__main__":
    app.run()
