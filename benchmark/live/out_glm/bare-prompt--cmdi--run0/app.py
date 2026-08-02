import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames or IPv4 only. No shell metacharacters can survive this.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _is_valid_host(host: str) -> bool:
    if not host:
        return False
    if _HOST_RE.match(host):
        return True
    # IPv4
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False


@app.get("/ping")
def ping():
    host = request.args.get("host", "").strip()

    if not _is_valid_host(host):
        return jsonify({"error": "invalid host"}), 400

    # Argument list (no shell) -> the validated host cannot inject commands.
    try:
        completed = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"host": host, "error": "timeout"}), 504

    return jsonify(
        {
            "host": host,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    )


if __name__ == "__main__":
    app.run()
