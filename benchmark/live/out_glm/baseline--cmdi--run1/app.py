import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames: letters, digits, dots, hyphens only. No shell metachars can pass.
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not _HOST_RE.match(host) or len(host) > 253:
        return jsonify({"error": "invalid host"}), 400

    # List form, no shell=True — argv is passed directly to exec, so the
    # validated host can never be interpreted as a shell command.
    result = subprocess.run(
        ["ping", "-c", "4", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return jsonify(
        {
            "host": host,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )


if __name__ == "__main__":
    app.run(debug=False)
