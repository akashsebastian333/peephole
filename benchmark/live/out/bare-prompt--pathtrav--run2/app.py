from flask import Flask, request, send_file
import os

app = Flask(__name__)
FILES_DIR = os.path.abspath('./files')

@app.route('/download')
def download():
    name = request.args.get('name', '')
    filepath = os.path.abspath(os.path.join(FILES_DIR, name))

    if not filepath.startswith(FILES_DIR) or not os.path.isfile(filepath):
        return 'Not found', 404

    return send_file(filepath)

if __name__ == '__main__':
    app.run()
