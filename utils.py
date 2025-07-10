"""
utils.py – helpers: thread‑pool, base64 iframe encoder, screenshot saver.
"""
from concurrent.futures import ThreadPoolExecutor
import base64, io, os
from PIL import Image

def pool(workers: int = 8) -> ThreadPoolExecutor:
    return ThreadPoolExecutor(max_workers=workers)

def b64_iframe(js: str) -> str:
    enc = base64.b64encode(js.encode()).decode()
    return f'<iframe srcdoc="&lt;script&gt;eval(atob(\'{enc}\'))&lt;/script&gt;"></iframe>'

def save_screenshot(driver, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(driver.get_screenshot_as_png())
