from flask import Flask, send_from_directory, request
import os
import os.path

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return "Missing 'name' parameter", 400

    filename = os.path.basename(name)
    filepath = os.path.join('./files', filename)

    try:
        return send_from_directory(os.path.dirname(filepath), os.path.basename(filepath))
    except FileNotFoundError:
        return "File not found", 404

if __name__ == '__main__':
    app.run(host="127.0.0.1")
