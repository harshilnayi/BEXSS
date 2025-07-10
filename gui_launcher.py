import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter.scrolledtext import ScrolledText
from threading import Thread, Event
import subprocess, sys

from xss_crawler import crawl
from xss_scanner import full_scan

root = tb.Window(themename="solar")
root.title("Browser XSS Automation Toolkit")
root.geometry("1024x720")
root.resizable(True, True)
root.state("zoomed")

tb.Label(root, text="🔥  Browser XSS Automation Toolkit  🔥",
         font=("Helvetica", 28, "bold"), bootstyle="danger").pack(pady=10)
frame = tb.Frame(root, padding=20); frame.pack(fill=BOTH, expand=True)

tb.Label(frame, text="Base URL:", font=("Helvetica", 14)).pack(anchor=W)
url_entry = tb.Entry(frame, width=120, font=("Helvetica", 12), bootstyle="info")
url_entry.pack(fill=X, pady=6)

row = tb.Frame(frame); row.pack(fill=X, pady=4)
depth_var = tb.IntVar(value=2)
tb.Label(row, text="Crawl Depth:", font=("Helvetica", 12)).pack(side=LEFT)
tb.Spinbox(row, from_=1, to=5, textvariable=depth_var, width=6,
           font=("Helvetica", 12), bootstyle="warning").pack(side=LEFT, padx=6)
waf_var = tb.BooleanVar()
tb.Checkbutton(row, text="Include WAF‑bypass payloads",
               variable=waf_var, bootstyle="danger").pack(side=LEFT, padx=12)

progress = tb.Progressbar(frame, mode="determinate", length=800,
                          bootstyle="success-striped", maximum=100)
progress.pack(fill=X, pady=10)
eta_lbl = tb.Label(frame, text="ETA: --", font=("Helvetica", 12, "bold"))
eta_lbl.pack(anchor=E)

log_box = ScrolledText(frame, height=18, font=("Consolas", 10),
                       bg="#0d1b2a", fg="#e0e1dd", insertbackground="white")
log_box.pack(fill=BOTH, expand=True, pady=8)
log_box.tag_config("vuln", foreground="#ff4f1a")
log_box.tag_config("safe", foreground="#3ec70b")
log_box.tag_config("info", foreground="#17a2b8")
def gui_log(msg, tag=None):
    log_box.after(0, lambda: (log_box.insert(END, msg, tag), log_box.see(END)))

def finish_bar(): progress["value"]=progress["maximum"]; eta_lbl.config(text="Done")
def pcb_factory():
    progress["value"]=0; progress["maximum"]=1; eta_lbl.config(text="ETA: --")
    def pcb(done,total,eta):
        progress.after(0, lambda:(progress.configure(value=done,maximum=total),
                                  eta_lbl.config(text=f"ETA: {eta}s" if eta else "ETA: <1s"),
                                  done>=total and finish_bar()))
    return pcb

stop_evt=Event()
def start_scan():
    base=url_entry.get().strip()
    if not base.startswith(("http://","https://")):
        gui_log("[!] Enter full http/https URL\n","safe");return
    depth, include=depth_var.get(),waf_var.get()
    stop_evt.clear()
    def worker():
        gui_log(f"[*] Crawling {base} (depth={depth})…\n","info")
        get_urls,post_forms=crawl(base,depth)
        if base not in get_urls:          # ensure manual URL is scanned!
            get_urls.insert(0,base)
        gui_log(f"[+] GET: {len(get_urls)}  POST: {len(post_forms)} targets\n","info")
        full_scan(base,get_urls,post_forms,include,gui_log,pcb_factory(),stop_evt)
        finish_bar()
    Thread(target=worker,daemon=True).start()
def stop_scan():
    stop_evt.set(); gui_log("[!] Stop requested…\n","safe")

btn_row=tb.Frame(frame); btn_row.pack(pady=10)
tb.Button(btn_row,text="🚀 Start Crawl & Scan 🚀",width=24,
          bootstyle="success-outline",command=start_scan).pack(side=LEFT,padx=10)
tb.Button(btn_row,text="🛑 Stop Scan",width=16,
          bootstyle="danger-outline",command=stop_scan).pack(side=LEFT,padx=10)

srv=tb.Frame(frame);srv.pack(pady=6)
def run(cmd,msg):subprocess.Popen([sys.executable,cmd],
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);gui_log(msg,"info")
tb.Button(srv,text="📦 Payload Server",width=18,
          bootstyle="info-outline",
          command=lambda:run("payload_server.py",
          "[*] Payload server http://localhost:8080/keylogger.js\n")).pack(side=LEFT,padx=8)
tb.Button(srv,text="🎧 C2 Listener",width=18,
          bootstyle="info-outline",
          command=lambda:run("c2_listener.py",
          "[*] Listener http://localhost:9000/log\n")).pack(side=LEFT,padx=8)

root.mainloop()
