import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, time, re, hashlib, base64
from datetime import datetime
import smtplib
from email.message import EmailMessage

# ===================== GLOBAL FLAGS =====================
stop_realtime = False
last_log_position = 0
log_file_path = ""

# ===================== AUTHENTICATION =====================
USER = "admin"
PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

def verify_password(p):
    return hashlib.sha256(p.encode()).hexdigest() == PASSWORD_HASH

# ===================== EMAIL CONFIG =====================
SENDER_EMAIL = "dandiyash8@gmail.com"
RECEIVER_EMAIL = "dandiyash8@gmail.com"
ENCODED_PASS = "ZmpvdyBob3RhIHdodXUga21lZQ=="  # base64 encoded app password

def send_alert_mail(subject, body):
    try:
        password = base64.b64decode(ENCODED_PASS).decode()
        msg = EmailMessage()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, password)
            server.send_message(msg)
    except Exception as e:
        print("Mail error:", e)

# ===================== DATA =====================
alerts = []
blocked_ips = set()
rules = []

# ===================== PREDEFINED RULES (50+) =====================
base_patterns = [
    ("SSH Brute Force", "failed password", "High"),
    ("Root Login Attempt", "root login", "Critical"),
    ("Port Scan", "port scan", "High"),
    ("SQL Injection", "select * from", "Critical"),
    ("XSS Attempt", "<script>", "High"),
    ("Malware Detected", "malware", "Critical"),
    ("Access Denied", "access denied", "Medium"),
    ("Unauthorized File", "unauthorized", "Medium"),
    ("Suspicious Download", ".exe", "Medium"),
    ("Suspicious Upload", "upload", "Medium"),
]

for i in range(1, 6):
    for name, pat, sev in base_patterns:
        rules.append({
            "name": f"{name} #{i}",
            "pattern": pat,
            "severity": sev
        })

# ===================== UTIL FUNCTIONS =====================
def extract_ip(text):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return match.group() if match else "N/A"

def raise_alert(rule, log_line):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = extract_ip(log_line)

    entry = f"{ts} | {rule['name']} | {rule['severity']} | {ip} | {log_line.strip()}"
    if entry in alerts:
        return

    alerts.append(entry)

    if ip != "N/A":
        blocked_ips.add(ip)

    if rule["severity"] in ["High", "Critical"]:
        send_alert_mail(
            f"[SIEM ALERT] {rule['name']}",
            f"Time: {ts}\nRule: {rule['name']}\nSeverity: {rule['severity']}\nIP: {ip}\n\n{log_line}"
        )

def check_rules(line):
    for rule in rules:
        if rule["pattern"].lower() in line.lower():
            raise_alert(rule, line)
            break

# ===================== LOG SCANNING =====================
def scan_logs(realtime=False):
    global stop_realtime, last_log_position

    if not log_file_path:
        messagebox.showwarning("Warning", "Select a log file first")
        return

    stop_realtime = False

    with open(log_file_path, "r") as f:
        if realtime:
            f.seek(last_log_position)
        else:
            last_log_position = 0
            alerts.clear()
            blocked_ips.clear()

        while True:
            line = f.readline()
            if not line:
                if realtime and not stop_realtime:
                    time.sleep(1)
                    continue
                break

            last_log_position = f.tell()
            check_rules(line)

            if stop_realtime:
                break

def stop_realtime_detection():
    global stop_realtime
    stop_realtime = True
    messagebox.showinfo("Info", "Real-time monitoring stopped.")

# ===================== REPORT =====================
def generate_report():
    if not alerts:
        messagebox.showinfo("Info", "No alerts to generate report.")
        return

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        initialfile=f"SIEM_Report_{datetime.now().strftime('%Y-%m-%d_%H%M')}.txt"
    )
    if not save_path:
        return

    with open(save_path, "w") as f:
        f.write("SIEM ALERT REPORT\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*80 + "\n\n")
        for a in alerts:
            f.write(a + "\n")

    messagebox.showinfo("Success", "Report generated successfully.")

# ===================== MAIN APP =====================
def launch_app():
    global log_file_path

    app = tk.Tk()
    app.title("Mini SIEM - Log Threat Detection")
    app.geometry("1100x650")
    app.configure(bg="black")

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook.Tab", background="black", foreground="lime")
    style.configure("Treeview", background="black", foreground="lime", fieldbackground="black")

    nb = ttk.Notebook(app)
    nb.pack(expand=True, fill="both")

    # ---------------- DASHBOARD ----------------
    dash = tk.Frame(nb, bg="black")
    nb.add(dash, text="Dashboard")

    lbl_stats = tk.Label(dash, fg="lime", bg="black", font=("Consolas", 16))
    lbl_stats.pack(pady=20)

    def select_log():
        global log_file_path
        log_file_path = filedialog.askopenfilename(
            filetypes=[("Log Files", ".log"), ("All Files", ".*")]
        )
        update_dashboard()

    tk.Button(dash, text="Select Log File", command=select_log,
              bg="black", fg="lime", width=30).pack(pady=5)
    tk.Button(dash, text="Scan Existing Logs",
              command=lambda: threading.Thread(target=scan_logs).start(),
              bg="black", fg="lime", width=30).pack(pady=5)
    tk.Button(dash, text="Start Real-Time Detection",
              command=lambda: threading.Thread(target=scan_logs, args=(True,)).start(),
              bg="black", fg="lime", width=30).pack(pady=5)
    tk.Button(dash, text="Stop Real-Time Detection",
              command=stop_realtime_detection,
              bg="black", fg="lime", width=30).pack(pady=5)
    tk.Button(dash, text="Generate Report",
              command=generate_report,
              bg="black", fg="lime", width=30).pack(pady=5)

    # ---------------- ALERTS ----------------
    alerts_tab = tk.Frame(nb, bg="black")
    nb.add(alerts_tab, text="Alerts")

    tree = ttk.Treeview(alerts_tab, columns=("Alert"), show="headings")
    tree.heading("Alert", text="Detected Alerts")
    tree.pack(expand=True, fill="both")

    # ---------------- RULES ----------------
    rules_tab = tk.Frame(nb, bg="black")
    nb.add(rules_tab, text="Rules")

    rule_list = ttk.Treeview(rules_tab, columns=("Name", "Pattern", "Severity"), show="headings")
    for c in ("Name", "Pattern", "Severity"):
        rule_list.heading(c, text=c)
    rule_list.pack(expand=True, fill="both")

    def refresh_rules():
        rule_list.delete(*rule_list.get_children())
        for r in rules:
            rule_list.insert("", "end", values=(r["name"], r["pattern"], r["severity"]))

    refresh_rules()

    entry_name = tk.Entry(rules_tab)
    entry_pat = tk.Entry(rules_tab)
    entry_sev = ttk.Combobox(rules_tab, values=["Low", "Medium", "High", "Critical"])

    for e in (entry_name, entry_pat, entry_sev):
        e.pack(pady=2)

    def add_rule():
        rules.append({
            "name": entry_name.get(),
            "pattern": entry_pat.get(),
            "severity": entry_sev.get()
        })
        refresh_rules()

    def delete_rule():
        sel = rule_list.selection()
        if not sel:
            return
        name = rule_list.item(sel)["values"][0]
        rules[:] = [r for r in rules if r["name"] != name]
        refresh_rules()

    tk.Button(rules_tab, text="Add Rule", command=add_rule,
              bg="black", fg="lime").pack(pady=5)
    tk.Button(rules_tab, text="Delete Selected Rule", command=delete_rule,
              bg="black", fg="lime").pack(pady=5)

    # ---------------- GUIDE ----------------
    guide_tab = tk.Frame(nb, bg="black")
    nb.add(guide_tab, text="Guide")

    guide_text = tk.Text(guide_tab, bg="black", fg="lime",
                         font=("Consolas", 12), wrap="word")
    guide_text.pack(expand=True, fill="both")
    guide_text.insert("end",
        "1. Login to the system\n"
        "2. Select a log file\n"
        "3. Scan existing logs or start real-time monitoring\n"
        "4. Alerts will appear automatically\n"
        "5. High and Critical alerts trigger email notifications\n"
        "6. Add or delete rules dynamically\n"
        "7. Generate reports when required\n"
    )
    guide_text.config(state="disabled")

    # ---------------- PROJECT DESCRIPTION ----------------
    proj_tab = tk.Frame(nb, bg="black")
    nb.add(proj_tab, text="Project Description")

    proj_text = tk.Text(proj_tab, bg="black", fg="lime",
                        font=("Consolas", 12), wrap="word")
    proj_text.pack(expand=True, fill="both")

    proj_text.insert("end", """
Project Information
-------------------
This project was developed by A. Sai teja, M. Lalith Chaitanya, Dilli Sumanth, Golu Kumar Gupta,
Vajrala Vamshi and V. Sonuteja as part of a Cyber Security Internship.

A Log-Based Threat Detection System monitors system and application logs to identify suspicious 
activities.It automatically sends email alerts to administrators for quick response to potential threats.

Project Details
---------------
Project Name         : Log Based Threat Detection System
Project Description  : Monitors logs for threats and sends email alerts to admins.
Project Start Date   : 16-Nov-2025
Project End Date     : 10-Jan-2026
Project Status       : Completed

Developer Details
-----------------
Name                | Employee ID
A. Sai teja         | ST#IS#7522
M. Lalith Chaitanya | ST#IS#7524
Dilli Sumanth       | ST#IS#7533
Golu kumar Gupta    | ST#IS#7541
Vajrala Vamshi      | ST#IS#7551
V. Sonuteja         | ST#IS#7553

Company Details
---------------
Company Name      : Supraja Technologies
Email             : contact@suprajaytechnologies.com
""")

    proj_text.config(state="disabled")

    # ---------------- AUTO REFRESH ----------------
    def update_dashboard():
        lbl_stats.config(
            text=f"Log File: {log_file_path}\n"
                 f"Total Alerts: {len(alerts)}\n"
                 f"Blocked IPs: {len(blocked_ips)}"
        )

    def update_alerts():
        tree.delete(*tree.get_children())
        for a in alerts:
            tree.insert("", "end", values=(a,))

    def auto_refresh():
        update_dashboard()
        update_alerts()
        app.after(2000, auto_refresh)

    auto_refresh()
    app.mainloop()

# ===================== LOGIN =====================
login = tk.Tk()
login.title("Login")
login.geometry("300x200")
login.configure(bg="black")

tk.Label(login, text="Username", fg="lime", bg="black").pack()
euser = tk.Entry(login)
euser.pack()

tk.Label(login, text="Password", fg="lime", bg="black").pack()
epass = tk.Entry(login, show="*")
epass.pack()

def do_login():
    if euser.get() == USER and verify_password(epass.get()):
        login.destroy()
        launch_app()
    else:
        messagebox.showerror("Error", "Invalid credentials")

tk.Button(login, text="Login", command=do_login,
          bg="black", fg="lime").pack(pady=10)

login.mainloop()