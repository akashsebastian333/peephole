import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Hostname per RFC 1123, or IPv4. Anything else is rejected at the boundary.
_HOST_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"
                      r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or len(host) > 253 or not _HOST_RE.match(host):
        return {"error": "invalid host"}, 400
    # argv form: no shell, so no shell metacharacter interpretation.
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True, text=True, timeout=5,
    )
    return {"output": result.stdout}


if __name__ == "__main__":
    app.run(host="127.0.0.1")
