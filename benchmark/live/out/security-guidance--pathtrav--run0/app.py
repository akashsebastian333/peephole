from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    path = os.path.realpath(os.path.join('files', name))
    base = os.path.realpath('files')

    if not path.startswith(base + os.sep) and path != base:
        abort(403)
    if not os.path.exists(path):
        abort(404)

    return send_file(path)

if __name__ == '__main__':
    app.run()
