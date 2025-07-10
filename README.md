
# Browser Exploit & XSS Automation Toolkit

A compact and effective penetration testing tool built to automate the discovery and exploitation of common XSS (Cross-Site Scripting) vulnerabilities. Designed with real-world offensive security needs in mind, this toolkit simplifies the otherwise manual process of scanning, exploiting, and managing XSS attack vectors.

---

## 💡 Why This Toolkit?

In most web security testing workflows, detecting XSS vulnerabilities can become time-consuming and inconsistent. This toolkit was developed to automate the process while offering modular control, payload deployment, and client session tracking — all in one place.

---

## 👥 Team Information

**Team Name:** Alpha  
**Team Members:**
- 🧑 Harshil  
- 🧑 Omkar  
- 🧑 Sumit

---

## 🔍 Features

- 🛰️ **Target Scanner** – Crawl and scan target URLs for XSS payload injection points.
- 💥 **Payload Deployment** – Launch curated and customizable XSS payloads.
- 🎯 **Reflected & Stored XSS Support** – Supports exploitation of both reflected and stored XSS vectors.
- 🧠 **DOM-Based XSS Handling** – Detects and interacts with vulnerable DOM contexts.
- 👁️ **Hooked Client Sessions** – Control panel to track and interact with victims post-exploitation.
- 🛠️ **C2 (Command & Control) Listener** – Real-time interface to manage hooked sessions.
- 🛡️ **Minimal Logging** – Basic activity logs for attack monitoring (without exposing sensitive info).

---

## 🧰 Tools & Technologies Used

- **Python 3.x**
- **Flask** (for lightweight backend routing)
- **HTML / JS** (for payloads and hooks)
- **SQLite3** (for basic log storage)
- **Ngrok / LocalTunnel** (optional, for exposing localhost)
- **PyInstaller** (for packaging the tool)

---

## 🧑‍💻 Usage Overview

1. **Start the C2 Listener**  
   Launch the control panel to prepare for client interaction.

2. **Scan Target URLs**  
   Use the toolkit's scanner to find injectable points and verify reflections.

3. **Deploy Payloads**  
   Select or craft payloads targeting specific injection points or DOM contexts.

4. **Wait for Hooked Sessions**  
   Once a victim triggers the payload, you gain visibility and control through the listener.

---

## ⚙️ Setup Instructions

> Prerequisites:
> - Python 3.x installed
> - Basic knowledge of terminal/command line

```bash
git clone https://github.com/your-username/xss-toolkit.git
cd xss-toolkit
pip install -r requirements.txt
python app.py
