import os
import hashlib
import json
import time
import webbrowser
import requests
from tkinter import *
from tkinter import filedialog, messagebox
from datetime import datetime
from colorama import Fore, Style, init
from threading import Thread, Event
from pyfiglet import Figlet
from fpdf import FPDF

# Library initialization
init(autoreset=True)
f = Figlet(font='slant')

# API configurations
VT_API_KEY = "1339c66fe0da65001c21b46b808ab92a6ae44f6278b16876a6264b5bf194c15a"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
LOG_FILE = "ascorbik_scan_log.json"
HEADERS = {
    "x-apikey": VT_API_KEY,
    "User-Agent": "ASCORBIK/1.7",
    "Accept-Encoding": "gzip, deflate"
}
QUARANTINE_DIR = "quarantine"
BACKUP_DIR = "malicious_backup"
REPORT_DIR = "reports"

for d in [QUARANTINE_DIR, BACKUP_DIR, REPORT_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

# Global variable for scanning
scan_active = Event()
scan_active.set()  # No scan in progress at startup

# -----------------------------
# Main functions
# -----------------------------
def calculate_sha256(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except Exception as e:
        log_output(f"{Fore.RED}[!] Error calculating SHA256: {e}")
        return None

def check_file_with_vt(sha256_hash):
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        try:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            vt_url = f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,
                "vt_url": vt_url
            }
        except Exception as e:
            log_output(f"{Fore.RED}[!] JSON parsing error: {e}")
            return {"error": "Invalid API response."}
    elif response.status_code == 404:
        return {"error": "File not found on VirusTotal."}
    else:
        return {"error": f"API error: {response.status_code}"}

def upload_file_to_vt(file_path):
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        response = requests.post(VIRUSTOTAL_API_URL, headers=HEADERS, files=files)
        if response.status_code == 200:
            try:
                analysis_id = response.json()['data']['id']
                log_output(f"{Fore.YELLOW}[~] File uploaded. Analysis in progress...")
                return get_analysis_result(analysis_id, file_path)
            except Exception as e:
                log_output(f"{Fore.RED}[!] Upload completed but analysis failed: {e}")
                return {"error": "Analysis interrupted during upload."}
        else:
            return {"error": f"Upload failed: {response.status_code}"}

def get_analysis_result(analysis_id, file_path=None):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        try:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            file_data = data.get("data", {}).get("relationships", {}).get("file", {}).get("data", {}).get("id", "")
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "vt_url": f"https://www.virustotal.com/gui/file/{file_data}/detection" if file_data else ""
            }
        except Exception as e:
            log_output(f"{Fore.RED}[!] Error parsing results: {e}")
            return {"error": "Unable to retrieve analysis results."}
    else:
        return {"error": "Unable to retrieve results."}

def scan_url_with_vt(url_to_scan):
    payload = {"url": url_to_scan}
    response = requests.post(VT_URL_SCAN_URL, headers=HEADERS, data=payload)
    if response.status_code == 200:
        try:
            analysis_id = response.json()['data']['id']
            log_output(f"{Fore.YELLOW}[~] URL sent. Waiting for results...")
            return get_url_analysis_result(analysis_id)
        except Exception as e:
            log_output(f"{Fore.RED}[!] Error analyzing URL: {e}")
            return {"error": "Unable to obtain analysis ID."}
    else:
        return {"error": f"Error analyzing URL: {response.status_code}"}

def get_url_analysis_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        try:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values())
            }
        except Exception as e:
            log_output(f"{Fore.RED}[!] Error parsing results: {e}")
            return {"error": "Unable to retrieve analysis results."}
    else:
        return {"error": "Unable to retrieve results."}

def log_output(message):
    console_text.config(state=NORMAL)
    console_text.insert(END, message + "\n")
    console_text.config(state=DISABLED)
    console_text.see(END)

def clear_console():
    console_text.config(state=NORMAL)
    console_text.delete("1.0", END)
    console_text.config(state=DISABLED)

def log_scan(target, result):
    scan_log = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "result": result
    }
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                json.dump([], f)
        with open(LOG_FILE, "r+") as f:
            logs = json.load(f)
            logs.append(scan_log)
            f.seek(0)
            json.dump(logs, f, indent=2)
    except Exception as e:
        log_output(f"{Fore.RED}[!] Error saving log: {e}")

def start_single_scan():
    path = file_entry.get().strip()
    if not path:
        messagebox.showwarning("Warning", "Enter a path or URL.")
        return
    scan_active.clear()  # Start scanning
    disable_all_inputs()
    scan_button.config(text="Scanning...", state=DISABLED)
    Thread(target=lambda: run_scan(path), daemon=True).start()

def run_scan(path):
    if os.path.isfile(path):
        scan_file(path)
    elif os.path.isdir(path):
        scan_folder(path)
    elif path.startswith("http"):
        scan_url(path)
    else:
        log_output(f"{Fore.RED}[!] Invalid path: {path}")
    scan_active.set()  # Scan finished
    enable_all_inputs()
    update_buttons()

def scan_file(file_path):
    if not scan_active.is_set():
        log_output(f"{Fore.CYAN}[+] Scanning file: {file_path}")
        sha256 = calculate_sha256(file_path)
        if not sha256:
            return
        result = check_file_with_vt(sha256)
        if "error" in result and "not present" in result["error"]:
            result = upload_file_to_vt(file_path)
        display_result(file_path, result)
        log_scan(file_path, result)

def scan_folder(folder_path):
    try:
        for root_dir, _, files in os.walk(folder_path):
            for f in files:
                if not scan_active.is_set():
                    log_output(f"{Fore.LIGHTBLACK_EX}[-] Scan interrupted by user.")
                    return
                file_path = os.path.join(root_dir, f)
                if os.path.getsize(file_path) == 0:
                    continue
                scan_file(file_path)
    except Exception as e:
        log_output(f"{Fore.RED}[!] Unable to access folder: {e}")
    update_buttons()

def scan_url(url):
    if not scan_active.is_set():
        log_output(f"{Fore.CYAN}[+] Scanning URL: {url}")
        result = scan_url_with_vt(url)
        display_result(url, result)
        log_scan(url, result)
    update_buttons()

def display_result(target, result):
    if "error" in result:
        log_output(f"{Fore.RED}[!] Result: {result['error']}")
    else:
        if result["malicious"] > 0:
            log_output(f"{Fore.RED}[⚠] WARNING: {target} is malicious.")
        elif result["suspicious"] > 0:
            log_output(f"{Fore.YELLOW}[!] Suspicious: {target}.")
        else:
            log_output(f"{Fore.GREEN}[✓] Safe: {target}.")

def stop_scanning():
    if scan_active.is_set():
        log_output(f"{Fore.LIGHTBLACK_EX}[-] No scan currently in progress to interrupt.")
        return
    confirm = messagebox.askyesno("Stop Scanning", "Are you sure you want to stop the scan?")
    if confirm:
        scan_active.set()  # Stop scanning
        log_output(f"{Fore.LIGHTBLACK_EX}[-] Scan stopped.")
        enable_all_inputs()
    update_buttons()

def generate_pdf_report():
    scan_data = []
    try:
        with open(LOG_FILE, "r") as f:
            scan_data = json.load(f)
    except Exception:
        log_output(f"{Fore.RED}[!] No log available for report.")
        return
    has_relevant_data = any(
        entry.get("result", {}).get("malicious", 0) > 0 or
        entry.get("result", {}).get("suspicious", 0) > 0
        for entry in scan_data
    )
    if not has_relevant_data:
        log_output(f"{Fore.RED}[!] No relevant data to export.")
        messagebox.showinfo("Empty Report", "No useful results to export. Perform at least one scan.")
        return
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Antivirus Scan Report - ASCORBIK v1.7", ln=True, align="C")
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True, align="L")
    pdf.ln(10)
    for entry in scan_data:
        target = entry.get("target", "[Target not found]")
        result = entry.get("result", {})
        pdf.cell(200, 10, txt=f"Target: {target}", ln=True)
        if isinstance(result, dict):
            malicious = result.get('malicious', 'N/A')
            suspicious = result.get('suspicious', 'N/A')
            undetected = result.get('undetected', 'N/A')
            pdf.cell(200, 10, txt=f"Malicious: {malicious}, Suspicious: {suspicious}, Undetected: {undetected}", ln=True)
        else:
            pdf.cell(200, 10, txt="[!] Unknown data.", ln=True)
        pdf.ln(5)
    report_path = os.path.join(REPORT_DIR, f"report_{int(time.time())}.pdf")
    pdf.output(report_path)
    log_output(f"{Fore.GREEN}[✓] PDF report generated: {report_path}")
    messagebox.showinfo("Report Generated", f"Saved at:\n{report_path}")

def browse_file():
    filename = filedialog.askopenfilename()
    if filename:
        file_entry.delete(0, END)
        file_entry.insert(0, filename)

def browse_folder():
    foldername = filedialog.askdirectory()
    if foldername:
        file_entry.delete(0, END)
        file_entry.insert(0, foldername)

def paste_text(event=None):
    try:
        text = root.clipboard_get()
        file_entry.delete(0, END)
        file_entry.insert(0, text)
    except:
        pass

def on_drop(event):
    dropped = event.data.strip('{}')
    file_entry.delete(0, END)
    file_entry.insert(0, dropped)

def update_buttons():
    scan_button.config(text="Scan", state=NORMAL if scan_active.is_set() else DISABLED)
    if not scan_active.is_set():
        stop_button.pack(side=LEFT, padx=5)
    else:
        stop_button.pack_forget()
    has_data = False
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
                has_data = any(
                    entry.get("result", {}).get("malicious", 0) > 0 or
                    entry.get("result", {}).get("suspicious", 0) > 0
                    for entry in data
                )
    except Exception:
        has_data = False
    if has_data:
        report_button.pack(side=LEFT, padx=5)
    else:
        report_button.pack_forget()
    root.update_idletasks()

def disable_all_inputs():
    file_entry.config(state=DISABLED)
    browse_button.config(state=DISABLED)
    folder_button.config(state=DISABLED)

def enable_all_inputs():
    file_entry.config(state=NORMAL)
    browse_button.config(state=NORMAL)
    folder_button.config(state=NORMAL)

# -----------------------------
# Graphical Interface (Tkinter)
# -----------------------------
root = Tk()
root.title("ASCORBIK v1.7 - Antimalware Scanner")
root.geometry("850x600")
root.configure(bg="#1e1e1e")

# ASCII Banner
ascii_art = f.renderText("ASCORBIK").strip().split('\n')
ascii_str = '\n'.join(ascii_art)
Label(root, text=ascii_str, font=("Courier New", 12), fg="#00ffcc", bg="#1e1e1e", justify=CENTER).pack(pady=10)

# Powered by
Label(root, text="Powered by Roy Merlo @2025", font=("Arial", 10), fg="#777777", bg="#1e1e1e").pack(pady=5)

# Input info
Label(root, text="You can enter a file, folder, or URL", font=("Arial", 10), fg="#aaaaaa", bg="#1e1e1e").pack(pady=5)

# Single input field
input_frame = Frame(root, bg="#1e1e1e")
input_frame.pack(pady=10)
file_entry = Entry(input_frame, width=60, font=("Consolas", 12), bg="#2d2d2d", fg="#ffffff", insertbackground="white")
file_entry.pack(side=LEFT, padx=5)
file_entry.bind("<Control-v>", paste_text)
file_entry.bind("<Button-3>", lambda e: root.focus_get().event_generate("<<Paste>>"))

browse_button = Button(input_frame, text="Browse", command=browse_file, width=10, bg="#FFD700", fg="black", relief=FLAT)
browse_button.pack(side=LEFT, padx=2)

folder_button = Button(input_frame, text="Folder", command=browse_folder, width=10, bg="#888888", fg="white", relief=FLAT)
folder_button.pack(side=LEFT, padx=2)

# Action buttons
action_frame = Frame(root, bg="#1e1e1e")
action_frame.pack(pady=10)
scan_button = Button(action_frame, text="Scan", command=start_single_scan, width=14, bg="#C0C0C0", fg="black", relief=FLAT)
scan_button.pack(side=LEFT, padx=5)

stop_button = Button(action_frame, text="Stop", command=stop_scanning, width=14, bg="#dc3545", fg="white", relief=FLAT)

report_button = Button(action_frame, text="Generate PDF Report", command=generate_pdf_report, width=16, bg="#28a745", fg="white", relief=FLAT)

# Console output
console_text = Text(root, wrap=WORD, state=DISABLED, height=20, bg="#2d2d2d", fg="#eeeeee", font=("Courier New", 10))
console_text.pack(padx=10, pady=10, expand=True, fill=BOTH)

# Start interface
update_buttons()
root.mainloop()