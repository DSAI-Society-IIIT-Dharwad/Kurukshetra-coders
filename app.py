import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys

# --- 1. SETUP THE FLASK APP ---
app = Flask(__name__)
# Allow our frontend to talk to our backend
CORS(app) 

# --- 2. COPY/PASTE ALL CHECK FUNCTIONS ---
# (These are from your old checks.py)

def check_headers(headers):
    """
    Analyzes response headers for common security misconfigurations.
    Returns a list of finding dictionaries.
    """
    local_findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    if 'content-security-policy' not in headers_lower:
        local_findings.append({
            "vulnerability": "Missing Content-Security-Policy (CSP) Header",
            "severity": "High",
            "details": "No CSP header found. This makes the site more vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
            "recommendation": "Implement a strong Content-Security-Policy header to control which resources (scripts, styles, images) are allowed to be loaded."
        })
    if 'x-frame-options' not in headers_lower:
        local_findings.append({
            "vulnerability": "Missing X-Frame-Options Header",
            "severity": "Medium",
            "details": "No X-Frame-Options header found. This could allow an attacker to embed your site in an iframe and perform 'clickjacking' attacks.",
            "recommendation": "Set 'X-Frame-Options: SAMEORIGIN' or 'DENY' to prevent your site from being loaded in a frame on other domains."
        })
    if 'x-content-type-options' not in headers_lower or headers_lower['x-content-type-options'].lower() != 'nosniff':
        local_findings.append({
            "vulnerability": "Missing or Incorrect X-Content-Type-Options",
            "severity": "Low",
            "details": "The 'X-Content-Type-Options: nosniff' header is missing or incorrect. This can lead to attacks where the browser misinterprets the content type of a file.",
            "recommendation": "Set the 'X-Content-Type-Options: nosniff' header."
        })
    return local_findings

def check_server_info(headers):
    """
    Checks for verbose server and tech headers.
    """
    local_findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    vulnerable_tech = {
        "php": ["5.6", "7.0", "7.1"], "apache": ["2.2"], "nginx": ["1.10"]
    }
    if 'server' in headers_lower:
        server = headers_lower['server'].lower()
        local_findings.append({
            "vulnerability": "Server Version Information Leak",
            "severity": "Low",
            "details": f"Server header is visible: {headers_lower['server']}",
            "recommendation": "Hide or obscure the 'Server' header to avoid revealing specific version information."
        })
        for tech, versions in vulnerable_tech.items():
            if tech in server and any(v in server for v in versions):
                local_findings.append({
                    "vulnerability": "Outdated Server Technology",
                    "severity": "High",
                    "details": f"Running a potentially vulnerable server version: {headers_lower['server']}",
                    "recommendation": "Update the server to the latest stable version."
                })
    if 'x-powered-by' in headers_lower:
        tech = headers_lower['x-powered-by'].lower()
        local_findings.append({
            "vulnerability": "Technology Information Leak (X-Powered-By)",
            "severity": "Medium",
            "details": f"Header reveals technology: {headers_lower['x-powered-by']}",
            "recommendation": "Disable or hide the 'X-Powered-By' header."
        })
        for tech_name, versions in vulnerable_tech.items():
            if tech_name in tech and any(v in tech for v in versions):
                local_findings.append({
                    "vulnerability": "Outdated Web Technology",
                    "severity": "High",
                    "details": f"Running a potentially vulnerable technology: {headers_lower['x-powered-by']}",
                    "recommendation": f"Update the technology (e.g., PHP, Express) to the latest stable version."
                })
    return local_findings

def check_exposed_files(base_url, session_headers):
    """
    Checks for common sensitive files.
    """
    print(f"Checking for exposed files on: {base_url}") # Debug print
    local_findings = []
    files_to_check = [
        '/robots.txt', '/.env', '/.git/config', '/sitemap.xml', 
        '/wp-config.php.bak', '/web.config'
    ]
    for file_path in files_to_check:
        test_url = urljoin(base_url, file_path)
        try:
            file_res = requests.head(test_url, headers=session_headers, timeout=5, allow_redirects=True)
            if file_res.status_code == 200:
                print(f"Found: {test_url}") # Debug print
                if file_path == '/.env':
                    get_res = requests.get(test_url, headers=session_headers, timeout=5)
                    if '<html>' in get_res.text.lower():
                        continue
                local_findings.append({
                    "vulnerability": "Exposed Sensitive File",
                    "severity": "High",
                    "details": f"The file '{file_path}' is publicly accessible at {test_url}",
                    "recommendation": f"Block public access to '{file_path}'. Review your server's access control rules."
                })
        except requests.exceptions.RequestException as e:
            print(f"Error checking {test_url}: {e}", file=sys.stderr) # Debug print for errors
            pass
    return local_findings

def check_vulnerability_patterns(url, html_content, session_headers):
    """
    Checks for simple error-based SQLi and passive XSS vulnerabilities.
    """
    local_findings = []
    
    # 1. Error-Based SQLi Check
    print("Checking for SQLi...") # Debug print
    sqli_payload = "'"
    if '?' in url:
        sqli_test_url = url + "&testparam=" + sqli_payload
    else:
        sqli_test_url = url + "?testparam=" + sqli_payload
    sql_error_patterns = [
        "sql syntax", "unclosed quotation mark", "mysql_fetch_assoc", 
        "you have an error in your sql syntax", "odbc driver", "invalid query"
    ]
    try:
        sqli_res = requests.get(sqli_test_url, headers=session_headers, timeout=5)
        if sqli_res.status_code == 500 or \
           any(pattern in sqli_res.text.lower() for pattern in sql_error_patterns):
            print("Found potential SQLi") # Debug print
            local_findings.append({
                "vulnerability": "Potential SQL Injection (Error-Based)",
                "severity": "Critical",
                "details": f"Sending a single quote payload to {sqli_test_url} returned a server error or SQL error message.",
                "recommendation": "Investigate immediately. Use parameterized queries (prepared statements) for all database interactions."
            })
    except requests.exceptions.RequestException as e:
        print(f"Error checking SQLi: {e}", file=sys.stderr) # Debug print
        pass

    # 2. Passive XSS Check (Finds forms)
    print("Checking for XSS entry points...") # Debug print
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = soup.find_all('form')
    if forms:
        form_count = 0
        for form in forms:
            inputs = form.find_all(['input', 'textarea'])
            if any(i.get('type') in ['text', 'search', 'email', 'password'] or i.name == 'textarea' for i in inputs):
                form_count += 1
        if form_count > 0:
            print(f"Found {form_count} XSS entry points (forms)") # Debug print
            local_findings.append({
                "vulnerability": "Potential Cross-Site Scripting (XSS) Entry Point",
                "severity": "Medium",
                "details": f"Found {form_count} form(s) with text inputs. These are common entry points for XSS.",
                "recommendation": "Ensure all user input is properly sanitized (HTML-escaped) on the server before being rendered back to the page."
            })
    return local_findings

# --- 3. CREATE THE CORE SCANNER LOGIC ---
# (This is from your old scanner.py)

def run_scan(target_url):
    """
    Runs the full scan on a target URL and returns a list of findings.
    """
    findings = []
    print(f"Starting scan on: {target_url}")
    
    # Pre-check: Ensure URL has http/https prefix
    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'http://' + target_url
        print(f"Defaulting to http. Full URL: {target_url}")
        
    try:
        session_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
        }
        response = requests.get(target_url, headers=session_headers, timeout=10)
        response.raise_for_status() 
        print("Successfully connected to target.")

        # --- Call Module Functions ---
        print("Checking headers...")
        findings.extend(check_headers(response.headers))
        
        print("Checking server info...")
        findings.extend(check_server_info(response.headers))
        
        print("Checking exposed files...")
        findings.extend(check_exposed_files(target_url, session_headers))
        
        print("Checking vulnerability patterns...")
        findings.extend(check_vulnerability_patterns(target_url, response.text, session_headers))
        
        print(f"Scan complete. Found {len(findings)} issues.")
        return findings

    except requests.exceptions.RequestException as e:
        print(f"FATAL SCAN ERROR: {e}", file=sys.stderr)
        # Return an error finding if the site can't be reached
        return [{
            "vulnerability": "Scan Error",
            "severity": "Critical",
            "details": f"Could not connect to or scan the target URL: {e}",
            "recommendation": "Check the URL and ensure the site is online. The server might be blocking scanners."
        }]

# --- 4. CREATE THE API ENDPOINT ---

@app.route('/scan', methods=['GET'])
def handle_scan():
    """
    This is the API endpoint the frontend will call.
    It takes a 'url' query parameter.
    """
    print("Received request at /scan endpoint.")
    target_url = request.args.get('url')
    if not target_url:
        print("Error: No URL provided in request.", file=sys.stderr)
        return jsonify({"error": "No URL provided"}), 400
    
    # Run the scan
    findings = run_scan(target_url)
    
    # Return the findings as JSON
    print("Returning findings as JSON.")
    return jsonify(findings)

# --- 5. RUN THE SERVER ---
if __name__ == '__main__':
    print("Starting Flask server on http://localhost:5000")
    print("Open scanner_app.html in your browser to use the tool.")
    # Set debug=False for a cleaner terminal, or True for more verbose error logging
    app.run(port=5000, debug=False)

