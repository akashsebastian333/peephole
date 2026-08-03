from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system(f'ping -c 1 {host}')
    return f'Ping result: {result}\n'

if __name__ == '__main__':
    app.run()
