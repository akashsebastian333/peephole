from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    return send_from_directory('./files', name)

if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        debug=os.environ.get('FLASK_DEBUG') == '1'
    )
