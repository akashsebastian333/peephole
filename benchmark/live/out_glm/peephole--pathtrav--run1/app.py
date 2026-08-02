import os
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        return "Missing 'name' parameter", 400

    # Sanitize the user-supplied name so it cannot escape FILES_DIR via
    # path traversal sequences (CWE-22).
    safe_name = secure_filename(name)
    if not safe_name:
        return "Invalid file name", 400

    file_path = os.path.join(FILES_DIR, safe_name)

    if not os.path.isfile(file_path):
        return "File not found", 404

    return send_file(file_path, as_attachment=True)


if __name__ == "__main__":
    app.run()
