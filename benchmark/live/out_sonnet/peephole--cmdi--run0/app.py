import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        return jsonify(error="invalid host"), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return jsonify(error="ping timed out"), 504

    return jsonify(output=result.stdout, returncode=result.returncode)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
