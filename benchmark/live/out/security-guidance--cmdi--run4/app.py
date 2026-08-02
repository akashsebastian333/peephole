from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    # WARNING: Command injection vulnerability - host parameter is not sanitized
    host = request.args.get('host', 'localhost')
    os.system(f"ping -c 1 {host}")
    return "Ping sent"

if __name__ == '__main__':
    app.run()
