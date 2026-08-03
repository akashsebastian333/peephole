import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# A hostname or IP: letters, digits, dots, hyphens only. No shell metacharacters,
# no spaces, no separators that could break out into a new argument.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    # Reject leading/trailing dots or hyphens and consecutive dots.
    if host.startswith(("-", ".")) or host.endswith(("-", ".")) or ".." in host:
        return False
    return bool(_HOST_RE.match(host))


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    if not _is_valid_host(host):
        return jsonify({"error": "invalid host"}), 400

    try:
        # Shell=False with an explicit argument list: no shell is ever spawned,
        # so the validated host can never be interpreted as a command separator.
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "ping timed out"}), 504

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
