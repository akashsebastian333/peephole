from flask import Flask, request, send_file
import os

app = Flask(__name__)
BASE_DIR = os.path.abspath('./files')

@app.route('/download')
def download():
    name = request.args.get('name', '')

    if not name:
        return 'Not found', 404

    filepath = os.path.abspath(os.path.join(BASE_DIR, name))

    if not filepath.startswith(BASE_DIR + os.sep):
        return 'Not found', 404

    if not os.path.isfile(filepath):
        return 'Not found', 404

    return send_file(filepath)

if __name__ == '__main__':
    app.run()
