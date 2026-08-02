import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.abspath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    safe_name = os.path.basename(name)
    if not safe_name or safe_name != name:
        abort(400)
    try:
        return send_from_directory(FILES_DIR, safe_name, as_attachment=True)
    except FileNotFoundError:
        abort(404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
