from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name', '')
    return send_from_directory('./files', os.path.basename(name))

if __name__ == '__main__':
    app.run()
