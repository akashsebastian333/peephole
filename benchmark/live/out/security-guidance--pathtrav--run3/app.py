from flask import Flask, send_file, request
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    file_path = os.path.join('./files', name)
    return send_file(file_path)

if __name__ == '__main__':
    app.run()
