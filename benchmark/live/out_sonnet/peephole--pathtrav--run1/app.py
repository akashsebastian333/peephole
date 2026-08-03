import os
from flask import Flask, abort, request, send_from_directory
from werkzeug.exceptions import NotFound

app = Flask(__name__)

FILES_DIR = os.path.realpath("./files")


@app.route("/download")
def download():
    name = os.path.basename(request.args.get("name", ""))
    try:
        return send_from_directory(FILES_DIR, name)
    except (FileNotFoundError, NotFound):
        abort(404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
