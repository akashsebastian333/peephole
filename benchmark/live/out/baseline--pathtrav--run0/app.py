from flask import Flask, send_file, request
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return 'Not found', 404

    file_path = os.path.join('./files', name)
    real_path = os.path.abspath(file_path)
    base_path = os.path.abspath('./files')

    if not real_path.startswith(base_path):
        return 'Not found', 404

    if not os.path.isfile(real_path):
        return 'Not found', 404

    return send_file(real_path)

if __name__ == '__main__':
    app.run()
