import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    os.system(f"ping -c 1 {host}")
    return f"Pinged {host}"

if __name__ == "__main__":
    app.run()
