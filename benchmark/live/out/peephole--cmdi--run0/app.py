from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return {'error': 'host parameter required'}, 400

    try:
        result = subprocess.run(['ping', '-c', '1', host],
                              capture_output=True,
                              timeout=5,
                              text=True)
        return {'output': result.stdout, 'return_code': result.returncode}
    except subprocess.TimeoutExpired:
        return {'error': 'ping timeout'}, 500
    except Exception as e:
        return {'error': str(e)}, 500

if __name__ == '__main__':
    app.run()
