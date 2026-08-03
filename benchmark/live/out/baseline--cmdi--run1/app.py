import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    exit_code = os.system(f'ping -c 1 {host}')
    return {'host': host, 'exit_code': exit_code}

if __name__ == '__main__':
    app.run(debug=True)
