import os

from flask import Flask, abort, request, send_from_directory
from werkzeug.exceptions import NotFound

app = Flask(__name__)

BASE_DIR = os.path.join(os.path.dirname(__file__), "files")


@app.route("/download")
def download():
    name = os.path.basename(request.args.get("name", ""))
    if not name:
        abort(400)
    try:
        return send_from_directory(BASE_DIR, name)
    except NotFound:
        abort(404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
