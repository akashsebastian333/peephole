from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name', '')
    base_dir = os.path.abspath('./files')
    requested_path = os.path.abspath(os.path.join(base_dir, name))

    if not requested_path.startswith(base_dir):
        abort(404)

    if not os.path.isfile(requested_path):
        abort(404)

    return send_file(requested_path)

if __name__ == '__main__':
    app.run()
