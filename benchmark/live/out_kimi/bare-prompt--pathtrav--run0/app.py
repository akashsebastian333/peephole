import os

from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.abspath(os.path.join(BASE_DIR, name))
    # Reject anything that escapes ./files (absolute paths, "..", symlink tricks aside).
    if os.path.commonpath((path, BASE_DIR)) != BASE_DIR or not os.path.isfile(path):
        return "not found", 404
    return send_file(path)


if __name__ == "__main__":
    app.run()
