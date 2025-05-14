# ASCORBIK 1.0

🛡️ **ASCORBIK** is an advanced open-source malware scanner written in Python. It integrates with the [VirusTotal API](https://www.virustotal.com) to perform file and URL scans, detect threats, and automatically quarantine malicious content. ASCORBIK features a user-friendly GUI, real-time logging, and recursive folder scanning for comprehensive protection.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/License-GPLv3-blue)
![Status](https://img.shields.io/badge/Version-1.7-success)

---

## ✨ Features

- ✅ **File Scanning** with SHA-256 fingerprinting
- 🌐 **URL Threat Analysis** via VirusTotal
- 🔄 **Auto Upload** of unknown files
- 📁 **Folder Scanning** with recursion
- 🧼 **Automatic Quarantine** of infected files
- 🧾 **JSON Logging** of all scan results
- 💡 **Multithreaded UI** for better performance
- 🎨 **Modern GUI** using Tkinter with styled console
- 🔒 **Optional Backup** before quarantine
- 📜 **GPLv3 License** for full open-source freedom

  
![ASCORBIK2](https://github.com/user-attachments/assets/9406034f-5a8a-4abd-b245-ac717fce0f13)

---

## 🚀 Getting Started

### ✅ Requirements

- Python 3.9 or higher
- VirusTotal API Key (Free or Premium)

### 📦 Install Dependencies

```bash
pip install -r requirements.txt
🔑 Insert Your VirusTotal API Key
Open the ascorbik.py file and replace the API key placeholder:VT_API_KEY = "your_virustotal_api_key"
🖥️ How to Use
python ascorbik.py
From the GUI:

Click "Scan File" to analyze a single file

Click "Scan Folder" to analyze a folder (recursive)

Enter a URL and click "Scan URL" to analyze web links

All results are saved to ascorbik_scan_log.json.

📁 Project Structure
bash
Copy
Edit
ASCORBIK/
├── ascorbik.py               # Main application
├── quarantine/               # Infected files quarantine
├── malicious_backup/         # Optional backup directory
├── reports/                  # Placeholder for future export (PDF)
├── ascorbik_scan_log.json    # JSON log file
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
🧠 Notes
Files submitted to VirusTotal may be shared with security vendors.

API usage is subject to VirusTotal's terms.

ASCORBIK is not a replacement for professional antivirus software.

🔐 License
ASCORBIK is licensed under the GNU General Public License v3.0.

You are free to use, modify, and distribute this software under the terms of the GNU GPL v3 License.

🤝 Contributing
Contributions, bug reports, and suggestions are welcome! Feel free to open an issue or submit a pull request.

✉️ Contact
Developed by Roy Merlo

For inquiries or collaboration: GitHub Profile

Powered by Roy Merlo — 2025


