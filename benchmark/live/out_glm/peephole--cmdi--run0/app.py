from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    try:
        subprocess.run(["ping", "-c1", host], shell=False, check=True, timeout=5)
    except subprocess.CalledProcessError:
        return "ping failed", 502
    except subprocess.TimeoutExpired:
        return "ping timeout", 504
    return "done"


if __name__ == "__main__":
    app.run()
