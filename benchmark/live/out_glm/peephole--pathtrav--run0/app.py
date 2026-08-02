import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


@app.route('/download')
def download():
    raw = request.args.get('name', '')
    base = os.path.realpath(FILES_DIR)
    safe = secure_filename(raw)
    if not safe:
        abort(404)
    path = os.path.realpath(os.path.join(base, safe))
    if not path.startswith(base + os.sep) or not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == '__main__':
    app.run()
