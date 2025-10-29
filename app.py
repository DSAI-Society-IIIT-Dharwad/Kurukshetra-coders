import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys

# --- 1. SETUP THE FLASK APP ---
print("Starting simple V-Scanner server...")
app = Flask(__name__)
# Allow our frontend to talk to our backend
# This is the "link" between the two files.
CORS(app) # Allow all origins

# --- 2. VULNERABILITY CHECK FUNCTIONS ---

def check_security_headers(headers):
    """Analyzes response headers for common security misconfigurations."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    if 'content-security-policy' not in headers_lower:
        findings.append({
            'severity': 'HIGH',
            'title': 'Missing Content-Security-Policy (CSP) Header',
            'details': 'No CSP header found. This makes the site more vulnerable to Cross-Site Scripting (XSS) and data injection attacks.',
            'recommendation': 'Implement a strong Content-Security-Policy header to control which resources (scripts, images, etc.) are allowed to be loaded on the page.'
        })
    if 'x-frame-options' not in headers_lower:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'Missing X-Frame-Options Header',
            'details': 'No X-Frame-Options header found. This could allow an attacker to embed your site in an iframe on their own malicious site (a "clickjacking" attack).',
            'recommendation': "Set 'X-Frame-Options: SAMEORIGIN' or 'DENY' to prevent your site from being framed by other domains."
        })
    if 'x-content-type-options' not in headers_lower or headers_lower['x-content-type-options'].lower() != 'nosniff':
        findings.append({
            'severity': 'LOW',
            'title': 'Missing X-Content-Type-Options Header',
            'details': "The 'X-Content-Type-Options: nosniff' header is not set. This can lead to the browser misinterpreting file types.",
            'recommendation': "Set 'X-Content-Type-Options: nosniff' to prevent the browser from MIME-sniffing the content-type."
        })
    if 'strict-transport-security' not in headers_lower:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'Missing Strict-Transport-Security (HSTS) Header',
            'details': 'The HSTS header is not set. This leaves the site vulnerable to man-in-the-middle attacks that downgrade HTTPS to HTTP.',
            'recommendation': 'Implement HSTS (e.g., \'Strict-Transport-Security: max-age=31536000; includeSubDomains\') to enforce HTTPS.'
        })
    return findings

def check_server_info(headers):
    """Looks for headers that leak server version or technology."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    if 'server' in headers_lower:
        findings.append({
            'severity': 'LOW',
            'title': 'Server Version Information Leak',
            'details': f"Server header is visible: {headers_lower['server']}",
            'recommendation': 'Hide or obscure the \'Server\' header to avoid giving attackers unnecessary information.'
        })
    if 'x-powered-by' in headers_lower:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'Technology Information Leak (X-Powered-By)',
            'details': f"Header reveals technology: {headers_lower['x-powered-by']}",
            'recommendation': "Disable or hide the 'X-Powered-By' header in your server's configuration."
        })
    return findings

def check_exposed_files(base_url, session):
    """Checks for a list of common sensitive files."""
    findings = []
    files_to_check = [
        '.env', '.git/config', 'wp-config.php', 'robots.txt', 'sitemap.xml'
    ]
    for file_path in files_to_check:
        file_url = urljoin(base_url, file_path)
        try:
            response = session.head(file_url, timeout=3, allow_redirects=False)
            if response.status_code == 200:
                is_sensitive = not any(safe_file in file_path for safe_file in ['robots.txt', 'sitemap.xml'])
                severity = 'HIGH' if is_sensitive else 'LOW'
                findings.append({
                    'severity': severity,
                    'title': f'Exposed File: {file_path}',
                    'details': f"The file '{file_path}' is publicly accessible at {file_url}.",
                    'recommendation': f"Review and restrict public access to '{file_path}' if it contains sensitive data."
                })
        except requests.RequestException:
            pass # File not found, which is good.
    return findings

def check_vulnerability_patterns(html_content):
    """Scans raw HTML for SQLi error patterns and potential XSS entry points."""
    findings = []
    soup = BeautifulSoup(html_content, 'html.parser')
    html_text = html_content.lower()

    # 1. Check for visible SQLi error messages
    sqli_patterns = [
        r"you have an error in your sql syntax", r"warning: mysql_fetch_array()",
        r"unclosed quotation mark", r"quoted string not properly terminated"
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, html_text, re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'Potential SQL Injection (Error-Based)',
                'details': f"The page content includes a database error message: '{pattern}'. This strongly suggests an SQL Injection vulnerability.",
                'recommendation': 'Use parameterized queries (prepared statements) for all database interactions and disable detailed server errors.'
            })
            break 

    # 2. Check for forms as potential XSS entry points
    forms = soup.find_all('form')
    if forms:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'Potential Cross-Site Scripting (XSS) Entry Point',
            'details': f"Found {len(forms)} form(s) on the page. These are common entry points for XSS attacks.",
            'recommendation': 'Ensure all user-supplied input is properly validated, sanitized, and output-encoded.'
        })
    return findings

# --- 3. SUMMARY CALCULATOR ---
def calculate_summary(findings):
    """Calculates the security score and counts for the dashboard."""
    weights = {
        'CRITICAL': 20,
        'HIGH': 15,
        'MEDIUM': 5,
        'LOW': 1
    }
    counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    total_penalty = 0
    
    for item in findings:
        severity = item['severity']
        if severity in counts:
            counts[severity] += 1
            total_penalty += weights.get(severity, 0)
            
    score = max(0, 100 - total_penalty)
    
    return {
        'score': score,
        'counts': counts,
        'total': len(findings)
    }

# --- 4. CORE SCAN FUNCTION ---
def run_scan(target_url):
    """Runs all checks on the target URL."""
    findings = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    with requests.Session() as session:
        session.headers.update(headers)
        
        try:
            response = session.get(target_url, timeout=10)
            response.raise_for_status() # Raise error for 4xx/5xx responses
            
            html_content = response.text
            response_headers = response.headers
            final_url = response.url # Use the final URL after redirects

            # Run all our checks
            findings.extend(check_security_headers(response_headers))
            findings.extend(check_server_info(response_headers))
            findings.extend(check_exposed_files(final_url, session))
            findings.extend(check_vulnerability_patterns(html_content))
            
        except requests.exceptions.RequestException as e:
            print(f"Error during scan: {e}", file=sys.stderr)
            findings.append({
                'severity': 'CRITICAL',
                'title': 'Scan Failed',
                'details': f"Could not connect to or scan the URL: {e}",
                'recommendation': 'Verify the URL is correct and the site is online. The server may be blocking scanners.'
            })
    return findings

# --- 5. API ENDPOINTS ---
@app.route('/health', methods=['GET'])
def health_check():
    """A simple endpoint to check if the server is running."""
    return jsonify({"status": "healthy", "message": "Server is up and running!"})

@app.route('/scan', methods=['POST'])
def handle_scan_post():
    """The main endpoint that the frontend calls."""
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
        
    target_url = data['url']
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url
        
    findings = run_scan(target_url)
    
    # Calculate the summary based on the findings
    summary_data = calculate_summary(findings) 
    
    # Return BOTH the report and the summary
    return jsonify({
        "report": findings,
        "summary": summary_data
    })

# --- 6. RUN THE SERVER ---
if __name__ == '_main_':
    print("Starting Flask server on http://127.0.0.1:5000")
    print("This server auto-reloads on code changes.")
    app.run(port=5000, debug=True)