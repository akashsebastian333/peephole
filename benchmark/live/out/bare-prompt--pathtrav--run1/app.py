from flask import Flask, send_file, request
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name', '')
    base = os.path.abspath('./files')
    file_path = os.path.abspath(os.path.join(base, name))

    try:
        if os.path.relpath(file_path, base).startswith('..'):
            return 'Not found', 404
    except ValueError:
        return 'Not found', 404

    if os.path.isfile(file_path):
        return send_file(file_path)
    return 'Not found', 404

if __name__ == '__main__':
    app.run()
