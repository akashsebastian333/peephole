from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host:
        return '', 400
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return {'stdout': result.stdout, 'returncode': result.returncode}

if __name__ == '__main__':
    import os
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
