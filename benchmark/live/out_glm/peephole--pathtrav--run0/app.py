import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


@app.route('/download')
def download():
    name = request.args.get('name', '')
    safe_name = secure_filename(name)
    if not safe_name:
        abort(404)
    path = os.path.join(FILES_DIR, safe_name)
    return send_file(path)


if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
