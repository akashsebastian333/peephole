from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return 'Missing name parameter', 400

    filename = os.path.basename(name)
    return send_from_directory('./files', filename)

if __name__ == '__main__':
    app.run()
