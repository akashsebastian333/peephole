import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

HOST_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\.\-]{0,253})[a-zA-Z0-9]$|^[a-zA-Z0-9]$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not HOST_RE.match(host):
        return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(host=host, exit_code=result.returncode, output=result.stdout)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
