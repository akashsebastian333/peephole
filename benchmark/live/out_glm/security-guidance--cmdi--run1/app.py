import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Allow only hostnames/IPv4/IPv6 — reject anything that smells like shell metacharacters.
_HOST_RE = re.compile(r"^[A-Za-z0-9.:\-]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not host or not _HOST_RE.match(host):
        return {"error": "invalid host"}, 400

    # No shell=True: `host` is passed as a single argv element, so it can never
    # be interpreted as a command, flag, or pipe.
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "timeout"}, 504

    return {
        "host": host,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


if __name__ == "__main__":
    app.run()
