import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Hostname or IPv4 only — no shell metacharacters can survive this.
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)*[a-zA-Z0-9](-?[a-zA-Z0-9])*$|^(\d{1,3}\.){3}\d{1,3}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not _HOST_RE.match(host):
        return "invalid host", 400
    # No shell: argv list, so the host string can never be reinterpreted as a command.
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "5", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout + result.stderr, 200 if result.returncode == 0 else 502


if __name__ == "__main__":
    app.run()
