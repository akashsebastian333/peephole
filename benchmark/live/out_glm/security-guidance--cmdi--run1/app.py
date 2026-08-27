import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames: letters, digits, dots, hyphens only. IPv4 covered by dotted-decimal.
# This rejects shell metacharacters at the boundary, so no shell is ever invoked.
_HOST_RE = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$")


def _is_valid_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    if _is_valid_ipv4(host):
        return True
    return bool(_HOST_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not _is_valid_host(host):
        return jsonify({"error": "invalid host"}), 400

    # subprocess with a list arg => no shell, no injection surface.
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"host": host, "alive": False, "error": "timeout"}), 504

    return jsonify(
        {
            "host": host,
            "alive": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )


if __name__ == "__main__":
    app.run()
