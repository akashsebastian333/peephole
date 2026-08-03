import os

from flask import Flask, abort, request, send_from_directory

BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))
MAX_NAME_LEN = 255

app = Flask(__name__)


def safe_target(name: str) -> str | None:
    """Resolve a user-supplied filename to an absolute path within BASE_DIR.

    Returns the resolved path if it is safe, or None if the name is
    missing, too long, contains path separators/traversal, or escapes
    the base directory.
    """
    if not name or len(name) > MAX_NAME_LEN:
        return None
    if os.sep in name or (os.altsep and os.altsep in name):
        return None
    if name in (".", "..") or name.startswith("."):
        return None

    target = os.path.realpath(os.path.join(BASE_DIR, name))
    if not (target == BASE_DIR or target.startswith(BASE_DIR + os.sep)):
        return None
    if not os.path.isfile(target):
        return None
    return target


@app.get("/download")
def download():
    name = request.args.get("name", "").strip()
    target = safe_target(name)
    if target is None:
        abort(404)
    return send_from_directory(BASE_DIR, os.path.basename(target))


if __name__ == "__main__":
    app.run()
