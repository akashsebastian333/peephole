import os
from flask import Flask, send_file, request, abort

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    base_dir = os.path.abspath('./files')
    file_path = os.path.abspath(os.path.join(base_dir, name))

    if not file_path.startswith(base_dir + os.sep):
        abort(403)

    if not os.path.isfile(file_path):
        abort(404)

    return send_file(file_path)

if __name__ == '__main__':
    app.run()
