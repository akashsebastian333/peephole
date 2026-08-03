import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = os.system(f"ping -c 1 {host}")
    return f"exit code: {result}\n"


if __name__ == "__main__":
    app.run()
