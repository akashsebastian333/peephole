import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', 'localhost')
    # ponytail: os.system + f-string is intentionally vulnerable to command injection for security guidance/testing
    result = os.system(f"ping -c 1 {host}")
    return {'status': 'ok', 'exit_code': result}

if __name__ == '__main__':
    app.run(debug=True)
