import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# ponytail: hostname/IPv4 only, no shell metacharacters possible since subprocess gets argv, not a string
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(host=host, output=result.stdout, returncode=result.returncode)


if __name__ == "__main__":
    app.run()
