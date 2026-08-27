import os
import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames: alphanumerics, dots, hyphens. IPs fit too. Anything else is rejected
# before it can reach the ping argv (keeps out leading-dash flags and garbage).
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        return jsonify({"error": "invalid host"}), 400
    # `--` ends option parsing so host can't be read as flags.
    proc = subprocess.run(
        ["ping", "-c", "1", "-W", "2", "--", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return jsonify({"exit_code": proc.returncode, "output": proc.stdout})


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
