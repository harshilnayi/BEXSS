"""
report_generator.py – neat PDF w/ zebra rows, cookie flag. CSV/HTML written by scanner.
"""
from datetime import datetime
from fpdf import FPDF
import pathlib, urllib.request, os

FONT = pathlib.Path("DejaVuSans.ttf")
if not FONT.exists():
    urllib.request.urlretrieve(
        "https://dejavu-fonts.github.io/downloads/DejaVuSans.ttf", FONT)

class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.add_font("DejaVu", "", str(FONT), uni=True)
        self.add_font("DejaVu", "B", str(FONT), uni=True)
        self.set_font("DejaVu", "", 11)

def generate_pdf(target: str, vulns: list[dict], elapsed: float,
                 out: str = "scan_report.pdf") -> str:
    pdf = PDF(); pdf.set_auto_page_break(True, 15); pdf.add_page()
    pdf.set_font("DejaVu", "B", 18); pdf.cell(0, 12, "XSS Scan Report", ln=1, align="C")
    pdf.set_font("DejaVu", "", 11)
    pdf.multi_cell(0, 7,
        f"Target : {target}\nGenerated: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"Duration: {elapsed:.2f}s\nVulns  : {len(vulns)}")
    pdf.ln(4)

    if not vulns:
        pdf.set_font("DejaVu", "B", 14); pdf.set_text_color(0,128,0)
        pdf.cell(0,10,"No vulnerabilities found.",ln=1,align="C")
        pdf.output(out); return out

    pdf.set_font("DejaVu", "B", 11)
    pdf.set_fill_color(30,30,30); pdf.set_text_color(255,255,255)
    headers = ["#", "Type", "Severity", "URL", "Cookies?"]
    widths  = [10,25,25,120,18]
    for h,w in zip(headers,widths): pdf.cell(w,8,h,1,0,"C",True)
    pdf.ln()
    pdf.set_font("DejaVu", "", 10)
    toggle = False
    for i,v in enumerate(vulns,1):
        toggle = not toggle
        pdf.set_fill_color(235,240,255) if toggle else pdf.set_fill_color(255,255,255)
        pdf.set_text_color(0,0,0)
        row = [str(i), v["type"], v["severity"],
               (v["url"][:110]+"…") if len(v["url"])>110 else v["url"],
               "✔" if v.get("cookies") else ""]
        for cell,w in zip(row,widths):
            pdf.cell(w,8,cell,1,0,"L",True)
        pdf.ln()
    pdf.output(out); return out
