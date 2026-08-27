import os
from flask import Flask, send_from_directory, request, abort

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name', '')
    if not name:
        abort(400)

    safe_name = os.path.basename(name)

    try:
        return send_from_directory('./files', safe_name)
    except FileNotFoundError:
        abort(404)

if __name__ == '__main__':
    app.run()
