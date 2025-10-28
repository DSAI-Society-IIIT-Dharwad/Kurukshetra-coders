<<<<<<< HEAD
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import logging
import validators
import threading
import uuid
from datetime import datetime
import io

from config import Config
from database import db
from models import ScanResult, Vulnerability
from scanners import (
    SQLInjectionScanner,
    XSSScanner,
    FileScanner,
    HeaderScanner,
    SSLScanner,
    VersionScanner
)
from utils.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize database
db.connect()

# Store active scans in memory
active_scans = {}

def perform_scan(scan_id, url):
    """Perform vulnerability scan in background"""
    try:
        logger.info(f"Starting scan {scan_id} for {url}")
        scan_result = ScanResult(url=url, scan_id=scan_id)
        active_scans[scan_id] = scan_result
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        scan_result.url = url
        
        # Initialize all scanners
        scanners = [
            SQLInjectionScanner(url),
            XSSScanner(url),
            FileScanner(url),
            HeaderScanner(url),
            SSLScanner(url),
            VersionScanner(url)
        ]
        
        # Run all scanners
        for scanner in scanners:
            try:
                scanner_name = scanner._class.name_
                logger.info(f"Running {scanner_name} on {url}")
                
                vulnerabilities = scanner.scan()
                
                for vuln in vulnerabilities:
                    scan_result.add_vulnerability(vuln)
                
                logger.info(f"{scanner_name} completed. Found {len(vulnerabilities)} issues")
                
            except Exception as e:
                logger.error(f"Error in {scanner._class.name_}: {e}")
                continue
        
        # Complete scan
        scan_result.complete_scan()
        logger.info(f"Scan {scan_id} completed successfully")
        
        # Save to database
        scan_data = scan_result.to_dict()
        db.save_scan(scan_data)
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id].fail_scan(str(e))

@app.route('/', methods=['GET'])
def home():
    """API home endpoint"""
    return jsonify({
        'service': 'Vulnerability Scanner API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'POST /api/scan': 'Start a new scan',
            'GET /api/scan/<scan_id>': 'Get scan results',
            'GET /api/scans': 'Get recent scans',
            'GET /api/report/<scan_id>': 'Download PDF report',
            'GET /api/health': 'Health check'
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected' if db.get_db() is not None else 'disconnected'
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'message': 'Please provide a URL in the request body'
            }), 400
        
        url = data['url'].strip()
        
        # Validate URL
        if not url:
            return jsonify({
                'error': 'Invalid URL',
                'message': 'URL cannot be empty'
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        if not validators.url(url):
            return jsonify({
                'error': 'Invalid URL format',
                'message': 'Please provide a valid URL'
            }), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=perform_scan,
            args=(scan_id, url)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        logger.info(f"Scan initiated: {scan_id} for {url}")
        
        return jsonify({
            'scan_id': scan_id,
            'url': url,
            'status': 'started',
            'message': 'Scan started successfully',
            'timestamp': datetime.utcnow().isoformat()
        }), 202
    
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    """Get scan results by ID"""
    try:
        # Check active scans first
        if scan_id in active_scans:
            scan_result = active_scans[scan_id]
            result_dict = scan_result.to_dict()
            
            # If scan is completed, remove from active scans
            if scan_result.status == 'completed':
                del active_scans[scan_id]
            
            return jsonify(result_dict), 200
        
        # Check database
        scan_data = db.get_scan(scan_id)
        
        if scan_data:
            return jsonify(scan_data), 200
        
        return jsonify({
            'error': 'Scan not found',
            'message': f'No scan found with ID: {scan_id}'
        }), 404
    
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/scans', methods=['GET'])
def get_recent_scans():
    """Get recent scans"""
    try:
        limit = request.args.get('limit', 10, type=int)
        limit = min(limit, 50)  # Max 50 scans
        
        scans = db.get_recent_scans(limit=limit)
        
        return jsonify({
            'scans': scans,
            'count': len(scans)
        }), 200
    
    except Exception as e:
        logger.error(f"Error retrieving recent scans: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/report/<scan_id>', methods=['GET'])
def download_report(scan_id):
    """Download PDF report for a scan"""
    try:
        # Get scan data
        scan_data = None
        
        if scan_id in active_scans:
            scan_result = active_scans[scan_id]
            if scan_result.status != 'completed':
                return jsonify({
                    'error': 'Scan not completed',
                    'message': 'Report can only be generated for completed scans'
                }), 400
            scan_data = scan_result.to_dict()
        else:
            scan_data = db.get_scan(scan_id)
        
        if not scan_data:
            return jsonify({
                'error': 'Scan not found',
                'message': f'No scan found with ID: {scan_id}'
            }), 404
        
        # Generate PDF report
        report_generator = ReportGenerator()
        pdf_data = report_generator.generate(scan_data)
        
        if not pdf_data:
            return jsonify({
                'error': 'Report generation failed',
                'message': 'Failed to generate PDF report'
            }), 500
        
        # Create file-like object
        pdf_buffer = io.BytesIO(pdf_data)
        pdf_buffer.seek(0)
        
        # Send file
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'vulnerability_report_{scan_id[:8]}.pdf'
        )
    
    except Exception as e:
        logger.error(f"Error generating report for {scan_id}: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get overall statistics"""
    try:
        scans = db.get_recent_scans(limit=100)
        
        total_scans = len(scans)
        total_vulnerabilities = sum(s.get('total_vulnerabilities', 0) for s in scans)
        
        severity_totals = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for scan in scans:
            breakdown = scan.get('severity_breakdown', {})
            for severity in severity_totals:
                severity_totals[severity] += breakdown.get(severity, 0)
        
        avg_score = sum(s.get('security_score', 0) for s in scans) / total_scans if total_scans > 0 else 0
        
        return jsonify({
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'severity_breakdown': severity_totals,
            'average_security_score': round(avg_score, 2)
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

if __name__ == '_main_':
    port = Config.FLASK_ENV == 'production' and 5000 or 5000
    logger.info(f"Starting Vulnerability Scanner API on port {port}")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=Config.DEBUG
    )
=======
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

>>>>>>> 9cead57b7ff4ed58bc9c9feb0f68faebf22a008c
