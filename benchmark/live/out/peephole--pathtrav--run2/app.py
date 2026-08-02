from flask import Flask, request, abort, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    safe_name = os.path.basename(name)
    return send_from_directory('./files', safe_name)

if __name__ == '__main__':
    app.run()
