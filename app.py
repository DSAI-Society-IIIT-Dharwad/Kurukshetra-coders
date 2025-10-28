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