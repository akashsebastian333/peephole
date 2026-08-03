from flask import Flask, request
import subprocess
import re

app = Flask(__name__)

# Allow only hostnames/IPs: letters, digits, dots, dashes, colons (IPv6).
# Using a safe argument list (no shell) prevents command injection from the
# 'host' query parameter.
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not host or not _HOST_RE.match(host):
        return {"error": "invalid host"}, 400
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}, 504


if __name__ == "__main__":
    app.run()
