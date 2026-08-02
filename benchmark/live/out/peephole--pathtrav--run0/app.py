from flask import Flask, send_from_directory, request

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    return send_from_directory('./files', name)

if __name__ == '__main__':
    app.run()
