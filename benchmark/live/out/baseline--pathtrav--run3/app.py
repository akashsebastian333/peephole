from flask import Flask, send_file, request
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return "Missing 'name' parameter", 400

    base_dir = os.path.abspath('./files')
    file_path = os.path.abspath(os.path.join(base_dir, name))

    if not file_path.startswith(base_dir):
        return "Access denied", 403

    if not os.path.isfile(file_path):
        return "File not found", 404

    return send_file(file_path)

if __name__ == '__main__':
    app.run()
