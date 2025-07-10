"""
xss_scanner.py  –  FINAL
• Thread‑pooled GET + POST
• Persistent cookies (requests.Session)
• Robust DOM detection:
    ① looks for window.__domxss flag
    ② OR detects payload string inside pageSource
    ③ OR detects Angular / template‑inject alert via console logs
• Saves screenshots
• Writes PDF, CSV, HTML
• Silences urllib3 InsecureRequestWarning
"""

from __future__ import annotations
import urllib.parse, time, os, json, csv, html, re, contextlib, warnings
import requests
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from utils import save_screenshot, pool
from xss_payloads import all_payloads, DOM
from report_generator import generate_pdf

# ── suppress HTTPS warnings ────────────────────────────
import urllib3
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

# ── globals ────────────────────────────────────────────
SEVERITY = {"Reflective": "High", "DOM": "Moderate"}
LOGFILE  = "scan_log.txt"
SESSION  = requests.Session()
open(LOGFILE, "w").close()        # reset log each run

# ── IO helpers ─────────────────────────────────────────
def _log_json(obj: dict): open(LOGFILE, "a", encoding="utf-8").write(
        json.dumps(obj, ensure_ascii=False) + "\n")

def _write_csv_html(rows: list[dict]):
    if not rows: return
    keys = rows[0].keys()
    # CSV
    with open("scan_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, keys); w.writeheader(); w.writerows(rows)
    # HTML
    with open("scan_report.html", "w", encoding="utf-8") as f:
        f.write("<html><body><h2>XSS Report</h2><table border=1>")
        f.write("<tr>" + "".join(f"<th>{html.escape(k)}</th>" for k in keys) + "</tr>")
        for r in rows:
            f.write("<tr>" + "".join(f"<td>"+html.escape(str(v))+"</td>" for v in r.values()) + "</tr>")
        f.write("</table></body></html>")

def _fmt(d: dict, sep="; "): return sep.join(f"{k}: {v}" for k, v in d.items())

# ── main orchestrator ─────────────────────────────────
def full_scan(base_url: str,
              get_urls: list[str],
              post_forms: list[tuple[str, dict]],
              include_waf: bool,
              log,
              pcb,
              stop_evt: Event):

    payloads = all_payloads(include_waf)
    total    = len(get_urls) + len(post_forms) + len(get_urls)  # GET + POST + DOM pass
    vulns, seen, start, done = [], set(), time.time(), 0

    def step():
        nonlocal done
        done += 1
        if pcb:
            eta = (time.time() - start) / max(done, 1) * (total - done)
            pcb(done, total, round(max(0, eta), 1))

    # Thread‑pooled GET & POST
    with pool() as executor:
        futs = [executor.submit(_scan_get, u, payloads, seen, vulns, log, stop_evt)
                for u in get_urls]
        futs += [executor.submit(_scan_post, a, f, payloads, seen, vulns, log, stop_evt)
                 for a, f in post_forms]
        for _ in as_completed(futs): step()

    # DOM pass (single thread)
    _scan_dom(get_urls, payloads, seen, vulns, log, stop_evt); step()

    if stop_evt.is_set():
        log("[!] Scan cancelled.\n", "safe"); return

    elapsed = time.time() - start
    pdf = generate_pdf(base_url, vulns, elapsed)
    _write_csv_html(vulns)
    log(f"[✓] Done in {elapsed:.2f}s – {len(vulns)} vulns. Reports saved.\n",
        "vuln" if vulns else "safe")

    if os.name == "nt":
        with contextlib.suppress(Exception):
            os.startfile(pdf)  # type: ignore

# ── worker helpers ────────────────────────────────────
def _replace(url, payload): return url.replace("FUZZ", urllib.parse.quote_plus(payload))

def _record(vtype, url, resp, vulns, log, seen, field="", shot=""):
    sig = url if not field else f"{url}|{field}"
    seen.add(sig)
    hdr = resp.headers if resp else {}
    ck  = resp.cookies.get_dict() if resp else {}
    vulns.append({"type": vtype, "severity": SEVERITY[vtype],
                  "url": url, "field": field, "headers": dict(hdr),
                  "cookies": ck, "screenshot": shot})
    _log_json({"type": vtype, "url": url, "headers": hdr, "cookies": ck})
    log(f"[VULN] {vtype} XSS → {url}\n", "vuln")
    if hdr: log("[+] headers: "+_fmt(hdr)+"\n", "info")
    if ck:  log("[+] cookies: "+_fmt(ck, ', ')+"\n", "info")
    if shot:log(f"[+] screenshot saved: {shot}\n", "info")

# ── GET / POST scanning ──────────────────────────────
def _scan_get(url, payloads, seen, vulns, log, stop):
    parsed = urllib.parse.urlparse(url)

    # direct FUZZ replacement
    if "FUZZ" in url:
        for pl in payloads:
            if stop.is_set(): return
            tgt = _replace(url, pl)
            if tgt in seen: return
            r = SESSION.get(tgt, timeout=8, verify=False)
            if pl in r.text:
                _record("Reflective", tgt, r, vulns, log, seen); return

    # parameter fuzz
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for param in qs:
        for pl in payloads:
            if stop.is_set(): return
            fuzz = qs.copy(); fuzz[param] = pl
            tgt = urllib.parse.urlunparse(parsed._replace(
                  query=urllib.parse.urlencode(fuzz, doseq=True)))
            if tgt in seen: return
            r = SESSION.get(tgt, timeout=8, verify=False)
            if pl in r.text:
                _record("Reflective", tgt, r, vulns, log, seen); return

def _scan_post(action, fields, payloads, seen, vulns, log, stop):
    for field in fields:
        for pl in payloads:
            if stop.is_set(): return
            sig = f"{action}|{field}"
            if sig in seen: return
            data = fields.copy(); data[field] = pl
            r = SESSION.post(action, data=data, timeout=8, verify=False)
            if pl in r.text:
                _record("Reflective", action, r, vulns, log, seen, field); return

# ── DOM scanning ─────────────────────────────────────
def _scan_dom(urls, payloads, seen, vulns, log, stop):
    opts = Options()
    opts.add_argument("--headless=new"); opts.add_argument("--disable-gpu")
    opts.add_argument("--log-level=3")
    drv = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    drv.set_page_load_timeout(30)

    dom_payloads = [p for p in payloads if p in DOM]
    for base_url in urls:
        if stop.is_set(): break
        base = base_url if "FUZZ" in base_url else (
               base_url + ("&FUZZ=" if "?" in base_url else "?FUZZ="))
        for pl in dom_payloads:
            if stop.is_set(): break
            tgt = _replace(base, pl)
            if tgt in seen: continue
            try:
                drv.get(tgt)
            except Exception:
                continue

            time.sleep(1)  # allow scripts

            # detection 1: flag variable
            if drv.execute_script("return window.__domxss||null") == 1:
                pass_detect = True
            # detection 2: raw payload appears in DOM
            elif pl.lower() in drv.page_source.lower():
                pass_detect = True
            else:
                # detection 3: any alert/console error containing our payload
                console = drv.get_log("browser") if "browser" in drv.log_types else []
                joined = " ".join(entry["message"] for entry in console)
                pass_detect = bool(re.search(r"alert\(1\)|__domxss|<svg", joined, re.I))

            if pass_detect:
                shot = f"screenshots/{int(time.time())}.png"
                save_screenshot(drv, shot)
                _record("DOM", tgt, None, vulns, log, seen, shot=shot)
                break
    drv.quit()
