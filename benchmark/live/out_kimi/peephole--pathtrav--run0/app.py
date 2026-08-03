import os

from flask import Flask, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args["name"]
    # send_from_directory uses safe_join: rejects ../ traversal with 404
    return send_from_directory(FILES_DIR, name, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
