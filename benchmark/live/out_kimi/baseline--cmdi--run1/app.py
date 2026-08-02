from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return "missing 'host' param", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout + result.stderr


if __name__ == "__main__":
    app.run()
