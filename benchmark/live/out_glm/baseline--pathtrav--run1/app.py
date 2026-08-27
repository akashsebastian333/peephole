import os
from flask import Flask, request, send_file

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        return "Missing 'name' parameter", 400
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        return "File not found", 404
    return send_file(path)


if __name__ == "__main__":
    app.run()
