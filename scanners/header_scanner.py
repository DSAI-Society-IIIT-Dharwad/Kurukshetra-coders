import requests
import logging
from models import Vulnerability
from utils import severity
from utils import recommendations
logger = logging.getLogger(__name__)

class HeaderScanner:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'MISSING_HSTS',
            'Content-Security-Policy': 'MISSING_CSP',
            'X-Frame-Options': 'MISSING_X_FRAME',
            'X-Content-Type-Options': 'MISSING_X_CONTENT_TYPE',
            'X-XSS-Protection': 'MISSING_XSS_PROTECTION',
            'Referrer-Policy': 'MISSING_REFERRER_POLICY'
        }
    
    def scan(self):
        """Scan for missing security headers"""
        vulnerabilities = []
        logger.info(f"Starting security header scan on {self.url}")
        
        try:
            response = requests.get(
                self.url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            headers = response.headers
            
            # Check for missing security headers
            for header_name, vuln_type in self.security_headers.items():
                if header_name not in headers:
                    severity = severity.get_severity(vuln_type)
                    recommendation = recommendations.get_recommendation(vuln_type)
                    
                    vuln = Vulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        description=f"Missing security header: {header_name}",
                        recommendation=recommendation['fix'],
                        evidence={
                            'missing_header': header_name,
                            'url': self.url
                        }
                    )
                    vulnerabilities.append(vuln)
            
            # Check for insecure headers
            if 'Server' in headers:
                server_header = headers['Server']
                if any(version in server_header.lower() for version in ['apache/2.2', 'apache/2.0', 'nginx/1.0', 'iis/6.0']):
                    vuln = Vulnerability(
                        vuln_type='OUTDATED_SOFTWARE',
                        severity='MEDIUM',
                        description=f"Outdated server version detected: {server_header}",
                        recommendation="Update web server to the latest stable version.",
                        evidence={
                            'server_header': server_header,
                            'url': self.url
                        }
                    )
                    vulnerabilities.append(vuln)
            
            # Check CORS configuration
            if 'Access-Control-Allow-Origin' in headers:
                cors_value = headers['Access-Control-Allow-Origin']
                if cors_value == '*':
                    vuln = Vulnerability(
                        vuln_type='CORS_MISCONFIGURATION',
                        severity='HIGH',
                        description="CORS allows any origin (*), which may expose sensitive data.",
                        recommendation="Configure CORS to allow only trusted domains.",
                        evidence={
                            'cors_header': cors_value,
                            'url': self.url
                        }
                    )
                    vulnerabilities.append(vuln)
            
            # Check for X-Powered-By header (information disclosure)
            if 'X-Powered-By' in headers:
                vuln = Vulnerability(
                    vuln_type='VERSION_DISCLOSURE',
                    severity='LOW',
                    description=f"X-Powered-By header discloses technology: {headers['X-Powered-By']}",
                    recommendation="Remove X-Powered-By header to avoid information disclosure.",
                    evidence={
                        'header_value': headers['X-Powered-By'],
                        'url': self.url
                    }
                )
                vulnerabilities.append(vuln)
            
        except requests.RequestException as e:
            logger.error(f"Error during header scan: {e}")
        
        logger.info(f"Header scan completed. Found {len(vulnerabilities)} issues")
        return vulnerabilities