import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return {"error": "missing 'host' query parameter"}, 400
    # Use an argument list (no shell) so the host is treated as a single
    # argument and cannot be interpreted as a shell command.
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"error": "ping timed out"}, 504
    return {
        "host": host,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


if __name__ == "__main__":
    app.run()
