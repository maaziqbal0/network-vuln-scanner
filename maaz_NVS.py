#!/usr/bin/env python3
import nmap
import time
import sys
import re
import smtplib
import json
from email.mime.text import MIMEText
from datetime import datetime

# Optional: For progress bar and pretty printing (install via pip if needed)
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# ---- Color Constants (ANSI Codes) ----
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ---- Utility Functions ----

def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return False
        return True
    return False

def get_port_range(port_range_str):
    if re.match(r'^\d+\-\d+$', port_range_str):
        start, end = port_range_str.split('-')
        start = int(start)
        end = int(end)
        if 1 <= start <= end <= 65535:
            return start, end
    return None

def send_email_notification(report_file, recipient_email, smtp_server, smtp_port, sender_email, sender_password):
    try:
        with open(report_file, "r") as f:
            report_content = f.read()
    except Exception as e:
        print(f"[-] Could not read report file for emailing: {e}")
        return

    msg = MIMEText(report_content)
    msg['Subject'] = f"Scan Report - {report_file}"
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print(f"[+] Email notification sent to {recipient_email}.")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")

def export_report(report_data, report_filename, format_type="txt"):
    try:
        if format_type == "txt":
            with open(report_filename, "w") as f:
                f.write(report_data)
        elif format_type == "json":
            with open(report_filename, "w") as f:
                json.dump(report_data, f, indent=4)
        # Additional formats (HTML, PDF) can be added here
        print(f"[+] Report exported to {report_filename}.")
    except Exception as e:
        print(f"[-] Error exporting report: {e}")

# ---- Banner + Menu ----

def show_banner():
    print(f"{RED}==============================================================={RESET}")
    print(f"{GREEN}  Wolf Maaz's Network Scanning Tool v1.1  |  (Ctrl+C to exit){RESET}")
    print(f"{RED}==============================================================={RESET}")
    print(f"{CYAN}Author  : Maaz Iqbal{RESET}")
    print(f"{CYAN}GitHub  : https://github.com/maaziqbal0/maaziqbal0{RESET}")
    print(f"{RED}===============================================================\n{RESET}")

def main_menu():
    show_banner()
    print("1) Start Scanning")
    print("2) Exit\n")
    choice = input("Enter your choice: ")
    if choice == "1":
        start_scanning()  # This will call the scanning logic
    elif choice == "2":
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice. Exiting...")
        sys.exit(1)

# ---- Scanning Logic ----

def start_scanning():
    scanner = nmap.PortScanner()

    # User Input: Target IP
    try:
        target = input("Target ka IP to btao...: ").strip()
        if not validate_ip(target):
            print("[-] Wrong IP hai yaar. Exiting.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading target IP: {e}")
        sys.exit(1)

    # User Input: Port Range
    port_range_str = input("Enter port range (e.g. 1-1024) [default 1-1024] Smhj nhi aarha to Default ke liye Enter press krlo: ").strip()
    if not port_range_str:
        port_range_str = "1-1024"
    port_range = get_port_range(port_range_str)
    if not port_range:
        print("[-] Invalid port range format. Exiting.")
        sys.exit(1)
    start_port, end_port = port_range
    port_spec = f"{start_port}-{end_port}"

    print(f"\nStarting scan on {target} from ports {port_spec}...\n")

    # ---- Scan Menu ----
    print("Select Scan Type:")
    print("1) SYN ACK Scan (Fast and Stealthy)")
    print("2) TCP Connect Scan (Comprehensive)")
    print("3) UDP Scan (For discovering UDP services)")
    print("4) Version Detection Scan (-sV)")
    print("5) OS Detection Scan (-O)")
    print("6) Script Scan (--script)")
    print("7) Confuse ho? Aggressive krlo (All in one: -A)")
    
    scan_choice = input("Kis type ka krna hai???(1/2/3/4/5/6/7): ").strip()
    args = ""
    if scan_choice == '1':
        print("\nPerforming SYN ACK Scan...")
        args = f"-sS -T4 -p {port_spec}"
    elif scan_choice == '2':
        print("\nPerforming TCP Connect Scan...")
        args = f"-sT -T4 -p {port_spec}"
    elif scan_choice == '3':
        print("\nPerforming UDP Scan... (May take time)")
        args = f"-sU -T4 -p {port_spec}"
    elif scan_choice == '4':
        print("\nPerforming Version Detection Scan...")
        args = f"-sV -T4 -p {port_spec}"
    elif scan_choice == '5':
        print("\nPerforming OS Detection Scan...")
        args = f"-O -T4 -p {port_spec}"
    elif scan_choice == '6':
        script_choice = input("Koi NSE script ya category daalni hai (jaise 'vuln' ya 'default). Default ke liye Enter press krlo: ").strip()
        if not script_choice:
            script_choice = "default"
        print(f"\nPerforming Script Scan using script category '{script_choice}'...")
        args = f"--script {script_choice} -T4 -p {port_spec}"
    elif scan_choice == '7':
        print("\nPerforming Aggressive Scan (All in one)...")
        args = f"-A -T4 -p {port_spec}"
    else:
        print("[-] Invalid option. Exiting.")
        sys.exit(1)

    # ---- Scanning with Progress Indicator ----
    print("[*] Scan in progress...")
    if tqdm:
        for _ in tqdm(range(10), desc="Scanning"):
            time.sleep(0.1)
    try:
        scanner.scan(target, arguments=args)
    except Exception as e:
        print(f"[-] Error during scanning: {e}")
        sys.exit(1)
    print("[*] Scan complete. Processing results...\n")

    # ---- Process and Display Scan Results ----
    report_data = {"target": target, "scan_type": scan_choice, "port_range": port_spec, "arguments": args, "results": []}
    report_txt = f"Scan Report for {target}\n"
    report_txt += f"Scan Type: {scan_choice}\nPort Range: {port_spec}\nNmap Arguments: {args}\n\n"

    console_output = ""
    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "protocols": {}
        }
        host_info = f"Host: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        report_txt += host_info
        console_output += host_info

        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            report_txt += "OS Detection:\n"
            console_output += "OS Detection:\n"
            os_list = []
            for os_data in scanner[host]['osmatch']:
                os_info = f"  - {os_data['name']} (Accuracy: {os_data['accuracy']}%)"
                os_list.append(os_info)
                report_txt += os_info + "\n"
                console_output += os_info + "\n"
            host_data["os_detection"] = os_list
        else:
            report_txt += "OS Detection: N/A\n"
            console_output += "OS Detection: N/A\n"
            host_data["os_detection"] = "N/A"
        
        for proto in scanner[host].all_protocols():
            proto_data = {}
            proto_heading = f"\nProtocol: {proto}\n"
            report_txt += proto_heading
            console_output += proto_heading
            lport = list(scanner[host][proto].keys())
            for port in sorted(lport):
                port_info = scanner[host][proto][port]
                service = port_info.get('name', 'N/A')
                state = port_info.get('state', 'N/A')
                version = port_info.get('version', 'N/A')
                port_entry = {"port": port, "state": state, "service": service, "version": version}
                proto_data[port] = port_entry
                port_line = f"Port: {port}\tState: {state}\tService: {service}\tVersion: {version}\n"
                report_txt += port_line
                console_output += port_line
            host_data["protocols"][proto] = proto_data

        separator = "\n" + ("-" * 40) + "\n\n"
        report_txt += separator
        console_output += separator
        report_data["results"].append(host_data)

    # ---- Export Report ----
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename_txt = f"scan_report_{target}_{timestamp}.txt"
    report_filename_json = f"scan_report_{target}_{timestamp}.json"
    export_report(report_txt, report_filename_txt, format_type="txt")
    export_report(report_data, report_filename_json, format_type="json")

    # ---- Print Detailed Results to Console ----
    print("=== DETAILED SCAN RESULTS ===")
    print(console_output)
    print("=== END OF RESULTS ===\n")

    # ---- Thank You Message & Recommendations ----
    print("Ye tool use karne ke liye bohot shukriya!")
    print("Agar aap aur deep me scanning explore karna chahte hain,toh...")
    print("Nmap | Nessus | Nikto jaisa tools ka use bhi kar sakte hain.\n")

    # ---- Email Notification Option ----
    email_choice = input("Do you want to send an email notification with the report? (y/n): ").strip().lower()
    if email_choice == 'y':
        recipient_email = input("Enter recipient email: ").strip()
        smtp_server = input("Enter SMTP server (e.g. smtp.gmail.com): ").strip()
        smtp_port = input("Enter SMTP port (e.g. 587): ").strip()
        sender_email = input("Enter sender email: ").strip()
        sender_password = input("Enter sender email password: ").strip()
        send_email_notification(report_filename_txt, recipient_email, smtp_server, int(smtp_port), sender_email, sender_password)

    print("[+] Scan complete. Reports generated and saved.")
    print("[*] Returning to main menu...\n")
    time.sleep(2)
    main_menu()

# ---- Program Entry Point ----

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Exiting...")
        sys.exit(0)
