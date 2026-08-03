from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)

FILES_DIR = os.path.abspath('./files')

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    filepath = os.path.abspath(os.path.join(FILES_DIR, name))
    relpath = os.path.relpath(filepath, FILES_DIR)

    if relpath.startswith('..'):
        abort(403)

    if not os.path.isfile(filepath):
        abort(404)

    return send_file(filepath)

if __name__ == '__main__':
    app.run()
