from flask import Flask, send_from_directory, request, abort
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    safe_filename = os.path.basename(name)
    return send_from_directory('./files', safe_filename)

if __name__ == '__main__':
    app.run(debug=False)
