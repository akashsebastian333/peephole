from flask import Flask, request
import os

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host:
        return {'error': 'missing host parameter'}, 400
    os.system(f'ping -c 1 {host}')
    return {'status': 'done', 'host': host}


if __name__ == '__main__':
    app.run()
