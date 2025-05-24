import time
from datetime import datetime
import subprocess
import signal
import sys
import requests
import os
import re
from urllib.parse import urlparse
from tqdm import tqdm

TARGET_URL = input("Enter the URL to scan: ")

# ZAP API Configuration
ZAP_BASE_URL = "http://localhost:9090"
API_KEY = "your api key"
zap_process = None
COMBINED_REPORT_FILENAME = "combined_report.txt"
API_URL = "http://localhost:8080/api/chat/completions"

# Kill processes on a port
def kill_process_on_port(port):
    try:
        result = subprocess.run(["lsof", "-t", f"-i:{port}"], capture_output=True, text=True)
        pids = result.stdout.strip().split("\n")
        if pids and pids[0]:
            for pid in pids:
                subprocess.run(["kill", "-9", pid], check=True)
            time.sleep(2)
        else:
            print(f"Port {port} is free.")
    except Exception as e:
        print(f"Error checking/killing processes on port {port}: {e}")

# Start Open WebUI in background
def start_open_webui():
    kill_process_on_port(8080)
    print("Starting Open WebUI in the background...")
    process = subprocess.Popen(
        ["bash", "-c", "DATA_DIR=~/.open-webui uvx --python 3.11 open-webui@latest serve &"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    print("Waiting for Open WebUI to start...")
    time.sleep(35)
    return process

# Check if Open WebUI is running
def check_open_webui():
    try:
        response = requests.get(API_URL)
        return response.status_code == 200
    except:
        return False

# Close Open WebUI
def close_open_webui(process):
    print("Closing Open WebUI...")
    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    kill_process_on_port(8080)
    print("Open WebUI closed.")

# Communicate with Open WebUI to summarize
def get_clean_summary(raw_text):
    payload = {
        "model": "gemma3:1b",
        "messages": [
            {"role": "system", "content": "Summarize and clean the following report content."},
            {"role": "user", "content": raw_text}
        ],
        "temperature": 0.7
    }

    headers = {
        "Authorization": "Bearer sk-8530180641364088ac461b549816102d",
        "Content-Type": "application/json",
        "x-jwt-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjVjMTkxN2IwLTdkNTQtNDY5MS1iYzgzLWE1MDdkMmI3MDE3ZiJ9.PwDNNv1ynrwOjO9-GIlfP38K4c9JJmy_0kb04fVg_sA"
    }

    response = requests.post(API_URL, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"]
    else:
        return f"[ERROR]: {response.text}"

# Main function to summarize and save report
def write_to_combined_report(report_section_title, content):
    if not check_open_webui():
        global open_webui_process
        open_webui_process = start_open_webui()
        # Wait and recheck
        while not check_open_webui():
            print("Waiting for Open WebUI to respond...")
            time.sleep(5)

    print("Summarizing content via AI...")
    summary = get_clean_summary(content)
    print("Saving summarized content to report...")
    fill_html_template_with_content(summary, "report.html")

    with open(COMBINED_REPORT_FILENAME, "a") as file:
        file.write(f"{report_section_title} - {datetime.now()}\n\n")
        file.write(summary + "\n\n")

def fill_html_template_with_content(cleaned_text, output_filename):
    # Sample HTML template – replace this with your own HTML structure
    html_template = """
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Security Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        .header {
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 2px solid #2c3e50;
            margin-bottom: 30px;
        }
        .tool-section {
            margin-bottom: 40px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }
        .tool-name {
            display: none;
        }
        .scan-type {
            background-color: #e8f4f8;
            padding: 10px 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-weight: bold;
        }
        .finding-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .finding-table th {
            background-color: #2c3e50;
            color: white;
            text-align: left;
            padding: 10px;
        }
        .finding-table td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        .finding-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .critical {
            color: #e74c3c;
            font-weight: bold;
        }
        .warning {
            color: #f39c12;
        }
        .info {
            color: #3498db;
        }
        .host-info {
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>Comprehensive Security Scan Report</h1>
            <p>Generated on: <span id="report-date">[AUTOMATIC_DATE]</span></p>
        </div>

        <div class="tool-section">
            <div class="host-info">
                <strong>Target:</strong> <br>
                <strong>Status:</strong> <br>
                <strong>DNS Record:</strong> 
            </div>

            <div class="scan-type">TCP Connect Scan</div>
            <table class="finding-table">
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Details</th>
                </tr>
            </table>

            <div class="scan-type">SYN Scan + Service Detection</div>
            <table class="finding-table">
                <tr>
                    <th>IP Address</th>
                    <th>Open Ports</th>
                    <th>Service</th>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td></td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td></td>
                </tr>
            </table>

            <div class="scan-type">Additional Findings</div>
            <ul>
                <li><span class="warning"></span> (no response)</li>
                <li>OS Detection: <span class="info"></span> </li>
                <li>Service Fingerprint: <span class="info"></span></li>
            </ul>

        <div class="tool-section">
            <div class="scan-type">Passive Scan</div>
            <table class="finding-table">
                <tr>
                    <th>Risk</th>
                    <th>Type</th>
                    <th>Location</th>
                </tr>
                <tr>
                    <td class="warning">Medium</td>
                    <td></td>
                    <td>/</td>
                </tr>
                <tr>
                    <td class="info">Low</td>
                    <td></td>
                    <td></td>
                </tr>
            </table>

            <div class="scan-type">Active Scan</div>
            <table class="finding-table">
                <tr>
                    <th>Risk</th>
                    <th>Vulnerability</th>
                    <th>Parameter</th>
                </tr>
                <tr>
                    <td class="critical">High</td>
                    <td>Cross-Site Scripting (Reflected)</td>
                    <td></td>
                </tr>
            </table>
        </div>

        <div class="tool-section">
            <table class="finding-table">
                <tr>
                    <th>Target URL</th>
                    <th>Vulnerable Parameter</th>
                    <th>DB Type</th>
                </tr>
                <tr>
                    <td></td>
                    <td class="critical"></td>
                    <td></td>
                </tr>
            </table>
            <ul>
                <li><span class="info"></span> </li>
                <li><span class="warning"></span> </li>
            </ul>
        </div>

        <div class="tool-section">
            <table class="finding-table">
                <tr>
                    <th>Test ID</th>
                    <th>Finding</th>
                    <th>Recommendation</th>
                </tr>
                <tr>
                    <td></td>
                    <td class="warning"></td>
                    <td></td>
                </tr>
            </table>
        </div>

        <div class="tool-section" style="background-color: #f8f9fa; padding: 20px; border-radius: 8px;">
            <h2>Key Findings Summary</h2>
            <ol>
                <li><span class="critical">Critical:</span> </li>
                <li><span class="critical">High:</span></li>
                <li><span class="warning">Medium:</span> </li>
                <li><span class="info">Info:</span> </li>
            </ol>
        </div>
   

  <div class="tool-section">
    <h2>🔧 General System Health</h2>
    <table class="finding-table">
        <tr><th>Status</th><th>Detail</th></tr>
        <tr><td></td><td></td></tr>
        <tr><td></td><td></td></tr>
        <tr><td class="warning">⚠</td><td></td></tr>
    </table>
</div>

<div class="tool-section">
    <h2>🛡 Boot and Security Services</h2>
    <table class="finding-table">
        <tr><th>Status</th><th></th></tr>
        <tr><td></td><td></td></tr>
        <tr><td class="warning">⚠</td><td></td></tr>
        <tr><td></td><td></td></tr>
        <tr><td class="danger"></td><td></td></tr>
        <tr><td></td><td></td></tr>
    </table>
</div>

<div class="tool-section">
    <h2>🚨 Service Security Status</h2>
    <ul>
        <li class="danger"></li>
        <li class="warning"></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h3></h3>
    <ul class="recommendation">
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h2>✅ Good</h2>
    <ul>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h3>⚠ Warnings / Suggestions</h3>
    <ul>
        <li class="warning"></li>
        <li class="warning"></li>
        <li class="warning"></li>
        <li class="warning"></li>
        <li class="warning"></li>
    </ul>
</div>

<div class="tool-section">
    <h3></h3>
    <ul>
        <li class="danger"></li>
        <li class="danger"></li>
    </ul>
</div>

<div class="tool-section">
    <h3>🔒 Recommended Next Steps</h3>
    <ul class="recommendation">
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h2>🔍 Metasploit & Nikto Web Scan Summary</h2>
    <ul>
        <li>Target: </li>
        <li>Server: </li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h3>Recommendations for Web Security</h3>
    <ul class="recommendation">
<div class="tool-section">
    <h2>🔍 Metasploit & Nikto Web Scan Summary</h2>
    <ul>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h3>Recommendations for Web Security</h3>
    <ul class="recommendation">
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<div class="tool-section">
    <h3>SQLMap Scan Result</h3>
    <ul>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>
 </div>

    <script>
        document.getElementById('report-date').textContent = new Date().toLocaleString();
    </script>
</body>
</html>

    """

    prompt = (
        "You are given a cleaned text and an HTML template. "
        "Automatically detect which parts of the text belong to which sections or columns in the HTML, "
        "and return the updated HTML with the content filled in the correct places. "
        "Preserve the HTML structure."
    )

    payload = {
        "model": "gemma3:1b",
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"CLEANED TEXT:\n{cleaned_text}\n\nHTML TEMPLATE:\n{html_template}"}
        ],
        "temperature": 0.7
    }

    headers = {
        "Authorization": "Bearer sk-8530180641364088ac461b549816102d",
        "Content-Type": "application/json",
        "x-jwt-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjVjMTkxN2IwLTdkNTQtNDY5MS1iYzgzLWE1MDdkMmI3MDE3ZiJ9.PwDNNv1ynrwOjO9-GIlfP38K4c9JJmy_0kb04fVg_sA"
    }

    response = requests.post(API_URL, json=payload, headers=headers)

    if response.status_code == 200:
        html_output = response.json()["choices"][0]["message"]["content"]
        
        # Save to .html file
        with open(output_filename, "w", encoding="utf-8") as file:
            file.write(html_output)
        
        return f"[SUCCESS] HTML content saved to '{output_filename}'"
    else:
        return f"[ERROR]: {response.text}"

def zap_save_output(report_filename, alerts_by_risk):
    with open(report_filename, "w") as file:
        content = f"ZAP Scan Report - {datetime.now()}\n\n"
        for risk, alert_list in alerts_by_risk.items():
            content += f"[{risk} Alerts]\n"
            for alert in alert_list:
                content += f"- {alert['alert']} ({alert['risk']}) - {alert['url']}\n"
            content += "\n"
        file.write(content)
        write_to_combined_report("ZAP Scan Report", content)


def nmap_save_output(target, scan_name, scan_result):
    """ Saves scan results to a text file in ZAP-style format. """
    report_filename = f"nmap_scan_{sanitize_filename(target)}.txt"
    extracted_info = extract_info(scan_result)

    content = f"Nmap Scan Report - {datetime.now()}\n\n"
    content += f"[{scan_name}]\n{scan_result}\n[Extracted Info]\n"
    for key, value in extracted_info.items():
        content += f"- {key}: {', '.join(value) if value else 'None'}\n"
    content += "\n"

    with open(report_filename, "a") as file:
        file.write(content)

    write_to_combined_report("Nmap Scan Report", content)
    print(f"Results saved to {report_filename}")


def lynis_save_output(target, scan_name, scan_result):
    """Saves scan results to a text file in ZAP-style format."""
    report_filename = f"lynis_audit_{sanitize_filename(target)}.txt"
    extracted_info = extract_info(scan_result)

    content = f"Lynis Audit Report - {datetime.now()}\n\n"
    content += f"[{scan_name}]\n{scan_result}\n[Extracted Info]\n"
    for key, value in extracted_info.items():
        content += f"- {key}: {', '.join(value) if value else 'None'}\n"
    content += "\n"

    with open(report_filename, "a") as file:
        file.write(content)

    write_to_combined_report("Lynis Audit Report", content)
    print(f"Report saved to {report_filename}")


def save_nikto_output(target, scan_name, scan_result):
    """Saves scan results to a text file in ZAP-style format."""
    report_filename = f"nikto_scan_{sanitize_filename(target)}.txt"
    extracted_info = extract_info(scan_result)

    content = f"Nikto Scan Report - {datetime.now()}\n\n"
    content += f"[{scan_name}]\n{scan_result}\n[Extracted Info]\n"
    for key, value in extracted_info.items():
        content += f"- {key}: {', '.join(value) if value else 'None'}\n"
    content += "\n"

    with open(report_filename, "a") as file:
        file.write(content)

    write_to_combined_report("Nikto Scan Report", content)
    print(f"Report saved to {report_filename}")


def meta_save_report(report, target):
    """Save gathered information to a file."""
    safe_target = target.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
    filename = f"metasploit_{safe_target}.txt"
    
    with open(filename, "w") as file:
        file.write(report)

    write_to_combined_report("Metasploit Report", report)
    print(f"[+] Progress saved to {filename}")


def sql_save_scan_results(target_url, scan_output, vulnerabilities):
    """Save full scan result and extracted vulnerabilities into a single file."""
    filename = f"sqlmap_scan_{sanitize_filename(target_url)}.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"SQLMap Scan Report - {timestamp}\n"
    content += f"Target URL: {target_url}\n\n[Scan Output]\n{scan_output}\n[Vulnerability Summary]\n"
    if vulnerabilities:
        content += "SQL Injection Vulnerabilities Found:\n"
        for vuln in vulnerabilities:
            content += f"- {vuln}\n"
    else:
        content += "No SQL Injection vulnerabilities detected.\n"

    with open(filename, "w") as file:
        file.write(content)

    write_to_combined_report("SQLMap Scan Report", content)
    print(f"Report saved to {filename}")


def sanitize_filename(target):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', target)

def cleanup_zap():
    print("Cleaning up existing ZAP processes and port 9090...")
    try:
        # Kill running zap processes
        zap_kill_cmd = "ps aux | grep zap | grep -v grep | awk '{print $2}'"
        zap_pids = subprocess.check_output(zap_kill_cmd, shell=True).decode().strip().split('\n')
        for pid in zap_pids:
            if pid.strip():
                os.kill(int(pid), signal.SIGKILL)

        # Free up port 9090
        port_kill_cmd = "lsof -t -i :9090"
        port_pids = subprocess.check_output(port_kill_cmd, shell=True).decode().strip().split('\n')
        for pid in port_pids:
            if pid.strip():
                os.kill(int(pid), signal.SIGKILL)

    except subprocess.CalledProcessError:
        # No processes or ports in use
        pass
    except Exception as e:
        print("Cleanup error:", e)

def run_zap_in_background_terminal():
    global zap_process
    print("Starting ZAP in the background...")
    
    zap_process = subprocess.Popen(
    ["/home/teja/ZAP_2.16.1/zap.sh", "-daemon", "-port", "9090"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

    print("Waiting for ZAP to start...")
    time.sleep(5)
    while True:
        try:
            response = requests.get(f"{ZAP_BASE_URL}/JSON/core/view/version/", params={"apikey": API_KEY})
            if response.status_code == 200:
                print("Hello! ZAP is running.")
                break
        except requests.exceptions.RequestException:
            time.sleep(1)

def terminate():
    print("Terminating ZAP...")
    try:
        os.system("ps aux | grep zap | grep -v grep | awk '{print $2}' | xargs -r sudo kill -9")
        os.system("sudo lsof -t -i :9090 | xargs -r sudo kill -9")
        print("terminated zap")
    except Exception as e:
        print("Error killing ZAP process:", e)
    print("compleated")

def start_spider_scan():
    url = f"{ZAP_BASE_URL}/JSON/spider/action/scan/?apikey={API_KEY}&url={TARGET_URL}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get("scan")
    return None

def start_active_scan():
    url = f"{ZAP_BASE_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={TARGET_URL}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get("scan")
    return None

def monitor_scan(scan_id, scan_type, endpoint):
    while True:
        status_url = f"{ZAP_BASE_URL}{endpoint}?apikey={API_KEY}&scanId={scan_id}"
        response = requests.get(status_url)
        if response.status_code == 200:
            status = response.json().get("status")
            print(f"{scan_type} Scan Progress: {status}%")
            if status == "100":
                break
        time.sleep(5)

def fetch_alerts():
    alerts_url = f"{ZAP_BASE_URL}/JSON/core/view/alerts/?apikey={API_KEY}&baseurl={TARGET_URL}"
    response = requests.get(alerts_url)
    if response.status_code == 200:
        return response.json().get("alerts", [])
    return []

def classify_alerts(alerts):
    categorized = {"High": [], "Medium": [], "Low": [], "Informational": []}
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        categorized[risk].append(alert)
    return categorized


def run_nmap_scan(target, scan_type):
    """
    Runs an Nmap scan with the specified target and scan type.
    """
    try:
        print(f"\nRunning {scan_type} scan on {target}...")
        result = subprocess.run(["nmap"] + scan_type.split() + [target], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def extract_info(scan_result):
    """ Extracts useful information from Nmap output."""
    ips = re.findall(r'Nmap scan report for (\S+)', scan_result)
    ports = re.findall(r'(\d+/\w+)\s+open', scan_result)
    os_info = re.findall(r'Running: (.*)', scan_result)
    return {
        "Live Hosts": ips,
        "Open Ports": ports,
        "OS Info": os_info
    }


def run_lynis_audit(target):
    """Run multiple Lynis system audits and return combined result."""
    try:
        commands = [
            (["sudo", "lynis", "audit", "system", "--quick", "--pentest"], "Quick Pentest Audit")
        ]
        
        all_results = ""
        for cmd, label in commands:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            all_results += f"\n=== {label} ===\n{result.stdout}\n"
        
        return all_results
    except subprocess.CalledProcessError as e:
        return f"Error running Lynis audit: {e}"

def extract_info(scan_result):
    """Dummy function to extract info (placeholder for real logic)."""
    return {
        "Warnings": [line for line in scan_result.splitlines() if "Warning" in line],
        "Suggestions": [line for line in scan_result.splitlines() if "Suggestion" in line]
    }



def check_server(target):
    """Check if the target is responding with an HTTP response."""
    try:
        response = subprocess.run(
            ["curl", "-Is", target], capture_output=True, text=True, timeout=5
        )
        return "HTTP" in response.stdout
    except subprocess.TimeoutExpired:
        return False

def extract_info(scan_result):
    """Extract useful information (stub for customization)."""
    # You can customize this to extract actual insights from Nikto output
    return {
        "Warnings": [line for line in scan_result.splitlines() if "WARNING" in line],
        "Findings": [line for line in scan_result.splitlines() if "+" in line]
    }



def run_nikto_scan(target):
    """Run Nikto scans for each tuning option on the target."""
    tuning_options = ["0", "1"]

    for tuning in tuning_options:
        if not check_server(target):
            print(f"Server not responding. Skipping scan {tuning}.")
            continue

        print(f"Starting Nikto scan with Tuning {tuning}...")
        try:
            process = subprocess.Popen(
                ["nikto", "-h", target, "-Tuning", tuning],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            start_time = time.time()
            timeout = 60  # Timeout per scan in seconds

            while process.poll() is None:
                if time.time() - start_time > timeout:
                    print(f"Scan {tuning} took too long. Terminating...")
                    process.terminate()
                    break
                time.sleep(5)

            stdout, stderr = process.communicate()
            scan_result = stdout + "\n" + stderr
            save_nikto_output(target, f"Tuning {tuning}", scan_result)

        except Exception as e:
            print(f"Error running scan {tuning}: {e}")

def run_msfconsole(command):
    """Run Metasploit console command and return output."""
    msf_command = f"msfconsole -q -x \"{command}; exit\""
    print(f"[DEBUG] Running: {command}")
    try:
        result = subprocess.run(msf_command, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out: {command}\n"



def gather_info(target, report):
    """Gather information about the target website."""
    report += f"[+] Target: {target}\n\n"
    
    # Identify Web Server
    report += "[+] Identifying Web Server:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/http_version; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    # Identify CMS
    report += "\n[+] Checking for WordPress:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/wordpress_scanner; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    # Directory Enumeration
    report += "\n[+] Directory Enumeration:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/dir_scanner; set RHOSTS {target}; set PATHS /admin/,/backup/,/uploads/; run")
    meta_save_report(report,target)
    
    # Config file exposure
    report += "\n[+] Checking for exposed config files:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/config_scanner; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    return report

def exploit(target, report):
    """Attempt to exploit vulnerabilities found."""
    report += "\n[+] Exploiting Vulnerabilities:\n"
    
    # Test for SQL Injection
    report += "\n[+] Testing for SQL Injection:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/sql_injection; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    # Test for LFI
    report += "\n[+] Testing for Local File Inclusion (LFI):\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/lfi_scanner; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    # Exploiting Joomla
    report += "\n[+] Testing Joomla Exploit:\n"
    report += run_msfconsole(f"use exploit/unix/webapp/joomla_http_header_rce; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    # Exploiting Drupal
    report += "\n[+] Testing Drupal Exploit:\n"
    report += run_msfconsole(f"use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS {target}; run")
    meta_save_report(report,target)
    
    return report

def brute_force(target, report):
    """Attempt to brute-force login credentials."""
    report += "\n[+] Brute-Force Attacks:\n"
    report += run_msfconsole(f"use auxiliary/scanner/http/http_login; set RHOSTS {target}; set USER_FILE users.txt; set PASS_FILE passwords.txt; run")
    meta_save_report(report,target)
    return report

def signal_handler(sig, frame):
    print("\n[!] Scan interrupted. Progress saved.")
    exit(0)

def run_sqlmap(target_url, filename):
    """Run SQLMap and write output to file live, with 10-minute timeout."""
    sqlmap_command = [
        "sqlmap", "-u", target_url, "--crawl=3", "--random-agent", "--batch",
        "--forms", "--level=5", "--risk=3"
    ]

    print(f"Running SQLMap on {target_url}...")

    process = subprocess.Popen(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    start_time = time.time()
    timeout = 300  # 10 minutes in seconds

    total_steps = 100  # Simulated progress
    with tqdm(total=total_steps, desc="Scanning Progress", unit="%") as pbar:
        with open(filename, "a") as file:
            for line in process.stdout:
                current_time = time.time()
                if current_time - start_time > timeout:
                    process.terminate()
                    print("\n⏱️ Timeout reached. Stopping the scan...")
                    break

                file.write(line)
                file.flush()

                line_lower = line.lower()

                # Simulated progress bar updates
                if "starting" in line_lower:
                    pbar.update(5)
                elif "testing" in line_lower:
                    pbar.update(20)
                elif "retrieving the length" in line_lower:
                    pbar.update(30)
                elif "retrieved" in line_lower:
                    pbar.update(45)
                elif "done" in line_lower:
                    pbar.update(100 - pbar.n)

                elapsed_time = current_time - start_time
                if pbar.n > 0:
                    eta = (elapsed_time / pbar.n) * 100 - elapsed_time
                    pbar.set_postfix(ETA=f"{eta:.2f}s")

    print("Scan completed or stopped due to timeout.")

    with open(filename, "r") as f:
        return f.read()

def extract_vulnerabilities(scan_output):
    """Extract potential SQL Injection vulnerabilities from scan output."""
    return [line.strip() for line in scan_output.splitlines() if re.search(r"Parameter.*is vulnerable", line, re.IGNORECASE)]





# ----------------------- MAIN -----------------------



def zap_main():
    cleanup_zap()
    run_zap_in_background_terminal()

    spider_id = start_spider_scan()
    if spider_id:
        monitor_scan(spider_id, "Spider", "/JSON/spider/view/status/")

    active_id = start_active_scan()
    if active_id:
        monitor_scan(active_id, "Active", "/JSON/ascan/view/status/")

    alerts = fetch_alerts()
    alerts_by_risk = classify_alerts(alerts)

    safe_url = TARGET_URL.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
    report_filename = f"all_{safe_url}.txt"

    zap_save_output(report_filename,alerts_by_risk)

    print(f"\nZAP Scan Completed. Report saved as: {report_filename}")
    terminate()

def nmap_main():
    parsed_url = urlparse(TARGET_URL)
    target = parsed_url.netloc
    scans = {
        "Ping Scan": "-sn",
        "TCP Connect Scan": "-sT",
        "SYN Scan": "-sS",
        "UDP Scan": "-sU",
        "Service Version Detection": "-sV",
        "OS Detection": "-O",
        "Aggressive Scan": "-A",
        "FIN Scan": "-sF",
        "Xmas Scan": "-sX",
        "Null Scan": "-sN",
        "Idle Scan": "-sI",
        "Script Scan": "--script=default",
        "Traceroute": "--traceroute",
        "Firewall Evasion": "-f"
    }

    for scan_name, scan_flag in scans.items():
        result = run_nmap_scan(target, scan_flag)
        extracted_info = extract_info(result)
        print(f"\n=== {scan_name} Results ===")
        print(result)
        print("Extracted Info:", extracted_info)
        nmap_save_output(target, scan_name, result)

def lynis_main():
    scan_name = "Full Lynis System Audit"
    scan_result = run_lynis_audit(TARGET_URL)
    lynis_save_output(TARGET_URL, scan_name, scan_result)

def nikto_main():
    target = TARGET_URL
    run_nikto_scan(target)
    print("All scans completed.")

def meta_main():
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    target = TARGET_URL
    report = ""
    
    print("[+] Gathering Information...")
    report = gather_info(target, report)
    
    print("[+] Running Exploits...")
    report = exploit(target, report)
    
    print("[+] Running Brute-Force Attacks...")
    report = brute_force(target, report)
    
    print("[+] Scan complete. Report saved to scan_report.txt")

def sql_main():
    target_url = TARGET_URL
    filename = f"sqlmap_scan_{sanitize_filename(target_url)}.txt"

    # Pre-create the file with a header
    with open(filename, "w") as file:
        file.write(f"SQLMap Scan Report - \n")
        file.write(f"Target URL: {target_url}\n\n")
        file.write("[Scan Output]\n")

    # Run scan and log live output
    scan_output = run_sqlmap(target_url, filename)
    vulnerabilities = extract_vulnerabilities(scan_output)

    # Append vulnerabilities at the end
    with open(filename, "a") as file:
        file.write("\n[Vulnerability Summary]\n")
        if vulnerabilities:
            file.write("SQL Injection Vulnerabilities Found:\n")
            for vuln in vulnerabilities:
                file.write(f"- {vuln}\n")
        else:
            file.write("No SQL Injection vulnerabilities detected.\n")

    print(f"Report saved to {filename}")

def main():
    zap_main()
    nmap_main()
    lynis_main()
    nikto_main()
    meta_main()
    sql_main()

if __name__ == "__main__":
    main()