import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

# Whitelist: hostname/IPv4/IPv6 chars only, no leading dash (blocks ping flags),
# no shell metacharacters. Passed as argv list anyway — belt and suspenders.
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:%-]{0,252}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not _HOST_RE.fullmatch(host):
        return jsonify({"error": "invalid host"}), 400
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping timed out"}), 504
    return jsonify(
        {"host": host, "returncode": result.returncode, "output": result.stdout}
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
