import requests
from bs4 import BeautifulSoup
import nmap
import os
import json
from datetime import datetime
from urllib.parse import urljoin
from flask import Flask, render_template
import time
import warnings

# Disable SSL warnings and other noisy warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

app = Flask(__name__)

class VulnerabilityScanner:
    def __init__(self):
        self.scan_results = []
        self.nm = nmap.PortScanner()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })

    def scan_web_application(self, target_url):
        """Perform comprehensive web application scan"""
        print(f"\n[+] Starting web application scan for {target_url}")
        
        self.check_security_headers(target_url)
        self.check_sensitive_files(target_url)
        self.test_sql_injection(target_url)
        self.test_xss(target_url)
        self.test_csrf(target_url)

    def scan_network(self, target_ip):
        """Perform network vulnerability scan"""
        print(f"\n[+] Starting network scan for {target_ip}")
        
        try:
            self.nm.scan(target_ip, arguments='-sV -T4')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        
                        if port in [21, 22, 23, 80, 443, 3389, 5900]:
                            severity = "Medium" if port in [21, 22, 23, 3389] else "Low"
                            self.add_vulnerability(
                                "Open Port Detected",
                                severity,
                                f"Port {port} ({service['name']}) is open",
                                f"Close if not needed or secure properly",
                                f"{host}:{port}"
                            )
        except Exception as e:
            print(f"Network scan error: {e}")

    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            response = self.session.get(url)
            headers = response.headers
            
            security_headers = {
                "X-XSS-Protection": "1; mode=block",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY or SAMEORIGIN",
                "Content-Security-Policy": "Present",
                "Strict-Transport-Security": "Present for HTTPS sites"
            }
            
            missing_headers = [h for h in security_headers if h not in headers]
            
            if missing_headers:
                self.add_vulnerability(
                    "Missing Security Headers",
                    "Medium",
                    f"Missing important security headers: {', '.join(missing_headers)}",
                    f"Implement the following security headers: {', '.join(missing_headers)}",
                    url
                )
        except Exception as e:
            print(f"Error checking security headers: {e}")

    def check_sensitive_files(self, url):
        """Check for exposed sensitive files"""
        sensitive_files = [
            "robots.txt", ".git/", ".env", 
            "wp-config.php", "phpinfo.php", 
            "server-status", "backup.zip"
        ]
        
        for file in sensitive_files:
            try:
                file_url = urljoin(url, file)
                response = self.session.get(file_url)
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Sensitive File Exposure",
                        "Medium",
                        f"Sensitive file accessible: {file_url}",
                        f"Restrict access to {file} or remove it",
                        file_url
                    )
            except Exception as e:
                continue

    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        forms = self.get_forms(url)
        test_payloads = ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"]
        
        for form in forms:
            for payload in test_payloads:
                form_data = self.prepare_form_data(form, payload)
                action = self.get_form_action(form, url)
                method = form.get("method", "get").lower()
                
                try:
                    if method == "post":
                        response = self.session.post(action, data=form_data)
                    else:
                        response = self.session.get(action, params=form_data)
                    
                    if self.is_sql_error(response.text):
                        self.add_vulnerability(
                            "SQL Injection",
                            "High",
                            f"Form at {action} is vulnerable to SQL injection",
                            "Use parameterized queries and input validation",
                            action
                        )
                except Exception as e:
                    continue

    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        forms = self.get_forms(url)
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for form in forms:
            for payload in test_payloads:
                form_data = self.prepare_form_data(form, payload)
                action = self.get_form_action(form, url)
                method = form.get("method", "get").lower()
                
                try:
                    if method == "post":
                        response = self.session.post(action, data=form_data)
                    else:
                        response = self.session.get(action, params=form_data)
                    
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            "High",
                            f"Form at {action} is vulnerable to XSS",
                            "Implement output encoding and CSP headers",
                            action
                        )
                except Exception as e:
                    continue

    def test_csrf(self, url):
        """Check for CSRF protection"""
        forms = self.get_forms(url)
        
        for form in forms:
            if not form.find("input", {"name": "csrf_token"}) and \
               not form.find("input", {"name": "csrfmiddlewaretoken"}):
                action = self.get_form_action(form, url)
                self.add_vulnerability(
                    "Potential CSRF Vulnerability",
                    "Medium",
                    f"Form at {action} lacks CSRF protection",
                    "Implement CSRF tokens and SameSite cookies",
                    action
                )

    def get_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all("form")
        except Exception as e:
            return []

    def prepare_form_data(self, form, payload):
        """Prepare form data with test payload"""
        form_data = {}
        for input_tag in form.find_all("input"):
            input_name = input_tag.get("name")
            input_type = input_tag.get("type", "text")
            input_value = input_tag.get("value", payload if input_type == "text" else "")
            form_data[input_name] = input_value
        return form_data

    def get_form_action(self, form, url):
        """Get form action URL"""
        action = form.get("action")
        return urljoin(url, action) if action else url

    def is_sql_error(self, text):
        """Check for SQL error messages in response"""
        sql_errors = [
            "SQL syntax", "MySQL server", "ORA-",
            "syntax error", "unclosed quotation mark",
            "PostgreSQL", "SQLite3", "Warning: mysql"
        ]
        return any(error.lower() in text.lower() for error in sql_errors)

    def add_vulnerability(self, title, severity, description, recommendation, location):
        """Add vulnerability to results"""
        vuln = {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "location": location,
            "timestamp": datetime.now().isoformat()
        }
        self.scan_results.append(vuln)
        print(f"[!] Found: {title} ({severity}) at {location}")

    def generate_json_report(self, filename="vulnerability_report.json"):
        """Generate JSON report"""
        report = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "scan_type": "Comprehensive Security Scan"
            },
            "findings": self.scan_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report generated: {filename}")

    def run_scan(self, target_url=None, target_ip=None):
        """Run complete scan"""
        if target_url:
            self.scan_web_application(target_url)
        if target_ip:
            self.scan_network(target_ip)
        
        self.generate_json_report()
        return self.scan_results

@app.route('/')
def dashboard():
    try:
        with open('vulnerability_report.json') as f:
            scan_data = json.load(f)
        return render_template('dashboard.html', findings=scan_data.get('findings', []))
    except FileNotFoundError:
        return render_template('dashboard.html', findings=[])

if __name__ == "__main__":
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create a simple dashboard template if it doesn't exist
    if not os.path.exists('templates/dashboard.html'):
        with open('templates/dashboard.html', 'w') as f:
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .vulnerability { margin-bottom: 20px; padding: 15px; border-left: 5px solid; }
        .critical { border-color: #ff0000; }
        .high { border-color: #ff6600; }
        .medium { border-color: #ffcc00; }
        .low { border-color: #33cc33; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Results</h1>
    {% for finding in findings %}
    <div class="vulnerability {{ finding.severity|lower }}">
        <h3>{{ finding.title }} ({{ finding.severity }})</h3>
        <p><strong>Location:</strong> {{ finding.location }}</p>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
        <p><em>Found at: {{ finding.timestamp }}</em></p>
    </div>
    {% else %}
    <p>No vulnerabilities found or scan not yet run.</p>
    {% endfor %}
</body>
</html>''')

    # Run the scanner
    scanner = VulnerabilityScanner()
    scanner.run_scan(
        target_url="http://testphp.vulnweb.com", 
        target_ip="127.0.0.1"
    )
    
    # Start Flask dashboard on alternate port if 5001 is in use
    port = 5001
    while True:
        try:
            app.run(host='0.0.0.0', port=port)
            break
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"Port {port} in use, trying {port + 1}")
                port += 1
            else:
                raise