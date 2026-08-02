from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)
BASE_DIR = os.path.abspath('./files')

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)
    file_path = os.path.abspath(os.path.join(BASE_DIR, name))
    if not file_path.startswith(BASE_DIR + os.sep):
        abort(403)
    return send_file(file_path)

if __name__ == '__main__':
    app.run()
