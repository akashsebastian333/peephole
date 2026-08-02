from flask import Flask, send_file, request
import os

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(__file__), 'files')

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return 'Missing name parameter', 400

    safe_name = os.path.basename(name)
    file_path = os.path.join(FILES_DIR, safe_name)

    if not os.path.exists(file_path):
        return 'File not found', 404

    return send_file(file_path)

if __name__ == '__main__':
    app.run()
