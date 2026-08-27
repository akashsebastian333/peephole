import os

from flask import Flask, request
from werkzeug.utils import safe_join, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    safe_path = safe_join(FILES_DIR, name)
    if safe_path is None or not os.path.isfile(safe_path):
        return "Not found", 404
    directory, filename = os.path.split(safe_path)
    return send_from_directory(directory, filename)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
