import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Strict hostname/IP allowlist: letters, digits, dots, hyphens only.
# Rejects anything containing shell metacharacters or whitespace.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    if ".." in host or host.startswith(".") or host.endswith("."):
        return False
    return bool(_HOST_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not _is_valid_host(host):
        return jsonify({"error": "invalid host"}), 400

    try:
        # List form (no shell=True): arguments are passed directly to the
        # process, so no shell interpretation can occur.
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504

    return jsonify(
        {
            "host": host,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )


if __name__ == "__main__":
    app.run()
