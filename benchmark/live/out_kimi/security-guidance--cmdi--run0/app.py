import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

_HOST_RE = re.compile(r"^[a-zA-Z0-9._:-]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not _HOST_RE.match(host):
        return jsonify({"error": "invalid host"}), 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping timed out"}), 504
    return jsonify({"output": result.stdout, "returncode": result.returncode})
