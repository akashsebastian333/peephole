import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Hostnames/IPs only; anything else is rejected before it nears a shell.
HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        return "invalid host", 400
    # No shell: args passed as a list, so host can't inject commands.
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=10
    )
    return result.stdout + result.stderr, 200 if result.returncode == 0 else 502
