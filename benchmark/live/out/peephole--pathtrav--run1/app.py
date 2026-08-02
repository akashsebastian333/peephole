from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    return send_from_directory(os.path.join('.', 'files'), name)

if __name__ == '__main__':
    app.run()
