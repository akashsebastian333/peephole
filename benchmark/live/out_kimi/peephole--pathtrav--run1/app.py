import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    # Drop any path components so ../ and absolute paths can't escape FILES_DIR.
    safe_name = os.path.basename(name)
    if not safe_name or safe_name != name or safe_name in (".", ".."):
        abort(400)
    full_path = os.path.abspath(os.path.join(FILES_DIR, safe_name))
    if os.path.dirname(full_path) != FILES_DIR or not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(FILES_DIR, safe_name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
