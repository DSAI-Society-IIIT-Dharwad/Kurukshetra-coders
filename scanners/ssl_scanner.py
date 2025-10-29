import ssl
import socket
import requests
import logging
from datetime import datetime
from urllib.parse import urlparse
from models import Vulnerability
from utils.severity import SeverityCalculator
from utils.recommendations import RecommendationEngine

logger = logging.getLogger(__name__)

class SSLScanner:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.hostname = urlparse(url).netloc.split(':')[0]
        self.port = 443
    
    def scan(self):
        """Scan for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting SSL/TLS scan on {self.url}")
        
        # Skip if not HTTPS
        if not self.url.startswith('https://'):
            logger.info("URL is not HTTPS, skipping SSL scan")
            return vulnerabilities
        
        try:
            # Check certificate validity
            context = ssl.create_default_context()
            
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        vuln = Vulnerability(
                            vuln_type='SSL_EXPIRED',
                            severity='CRITICAL',
                            description=f"SSL certificate expired {abs(days_until_expiry)} days ago.",
                            recommendation=RecommendationEngine.get_recommendation('SSL_EXPIRED')['fix'],
                            evidence={
                                'expiry_date': cert['notAfter'],
                                'days_expired': abs(days_until_expiry)
                            }
                        )
                        vulnerabilities.append(vuln)
                    elif days_until_expiry < 30:
                        vuln = Vulnerability(
                            vuln_type='SSL_EXPIRING_SOON',
                            severity='MEDIUM',
                            description=f"SSL certificate expires in {days_until_expiry} days.",
                            recommendation="Renew SSL certificate before expiration.",
                            evidence={
                                'expiry_date': cert['notAfter'],
                                'days_remaining': days_until_expiry
                            }
                        )
                        vulnerabilities.append(vuln)
                    
                    # Check protocol version
                    protocol = ssock.version()
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                    if protocol in weak_protocols:
                        vuln = Vulnerability(
                            vuln_type='SSL_WEAK_PROTOCOL',
                            severity='HIGH',
                            description=f"Weak SSL/TLS protocol in use: {protocol}",
                            recommendation="Disable weak protocols and use TLS 1.2 or higher.",
                            evidence={
                                'protocol': protocol
                            }
                        )
                        vulnerabilities.append(vuln)
                    
                    # Check cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            vuln = Vulnerability(
                                vuln_type='SSL_WEAK_CIPHER',
                                severity='HIGH',
                                description=f"Weak cipher suite detected: {cipher_name}",
                                recommendation=RecommendationEngine.get_recommendation('SSL_WEAK_CIPHER')['fix'],
                                evidence={
                                    'cipher': cipher_name,
                                    'protocol': cipher[1],
                                    'bits': cipher[2]
                                }
                            )
                            vulnerabilities.append(vuln)
        
        except ssl.SSLError as e:
            logger.warning(f"SSL error: {e}")
            vuln = Vulnerability(
                vuln_type='SSL_ERROR',
                severity='HIGH',
                description=f"SSL/TLS error: {str(e)}",
                recommendation="Check SSL certificate configuration and validity.",
                evidence={'error': str(e)}
            )
            vulnerabilities.append(vuln)
        
        except socket.timeout:
            logger.error("SSL scan timeout")
        
        except Exception as e:
            logger.error(f"Error during SSL scan: {e}")
        
        # Check if HTTPS is enforced
        try:
            http_url = self.url.replace('https://', 'http://')
            response = requests.get(http_url, timeout=self.timeout, allow_redirects=False, verify=False)
            
            if response.status_code != 301 and response.status_code != 302:
                vuln = Vulnerability(
                    vuln_type='HTTPS_NOT_ENFORCED',
                    severity='MEDIUM',
                    description="HTTP requests are not automatically redirected to HTTPS.",
                    recommendation="Configure server to redirect all HTTP traffic to HTTPS.",
                    evidence={
                        'http_url': http_url,
                        'status_code': response.status_code
                    }
                )
                vulnerabilities.append(vuln)
        except:
            pass
        
        logger.info(f"SSL scan completed. Found {len(vulnerabilities)} issues")
        return vulnerabilities