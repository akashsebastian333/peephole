from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

FILES_DIR = os.path.abspath('./files')

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    file_path = os.path.abspath(os.path.join(FILES_DIR, name))

    if not file_path.startswith(FILES_DIR + os.sep) and file_path != FILES_DIR:
        abort(403)

    if not os.path.isfile(file_path):
        abort(404)

    return send_file(file_path)

if __name__ == '__main__':
    app.run()
