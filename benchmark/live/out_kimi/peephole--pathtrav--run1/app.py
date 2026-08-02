import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


@app.route("/download")
def download():
    name = os.path.basename(request.args.get("name", ""))
    if not name:
        abort(400)
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
