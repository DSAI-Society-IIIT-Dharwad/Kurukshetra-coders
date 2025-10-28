import requests
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from models import Vulnerability
from utils import severity
from utils import recommendations

logger = logging.getLogger(__name__)

class XSSScanner:
    def _init_(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "javascript:alert('XSS')",
            "<IMG SRC=\"javascript:alert('XSS');\">",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>"
        ]
    
    def scan(self):
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting XSS scan on {self.url}")
        
        try:
            # Get the page
            response = requests.get(self.url, timeout=self.timeout, verify=False)
            
            if response.status_code != 200:
                return vulnerabilities
            
            # Parse HTML to find forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Test each form
            for form in forms:
                vuln = self._test_form(form, response.url)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Test URL parameters
            parsed_url = urlparse(self.url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    vuln = self._test_url_parameter(param)
                    if vuln:
                        vulnerabilities.append(vuln)
            
        except Exception as e:
            logger.error(f"Error during XSS scan: {e}")
        
        logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _test_form(self, form, base_url):
        """Test a form for XSS"""
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Build form URL
            if action:
                form_url = urljoin(base_url, action)
            else:
                form_url = base_url
            
            # Get form inputs
            inputs = form.find_all(['input', 'textarea'])
            form_data = {}
            
            # Try XSS payload in each input
            for payload in self.payloads[:3]:  # Test with first 3 payloads
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    
                    if not input_name or input_type in ['submit', 'button']:
                        continue
                    
                    # Build form data
                    form_data = {input_name: payload}
                    
                    # Fill other inputs with dummy data
                    for other_input in inputs:
                        other_name = other_input.get('name')
                        if other_name and other_name != input_name:
                            form_data[other_name] = 'test'
                    
                    # Submit form
                    try:
                        if method == 'post':
                            response = requests.post(form_url, data=form_data, timeout=self.timeout, verify=False)
                        else:
                            response = requests.get(form_url, params=form_data, timeout=self.timeout, verify=False)
                        
                        # Check if payload is reflected without encoding
                        if payload in response.text:
                            vuln_type = 'XSS_REFLECTED'
                            severity = severity.get_severity(vuln_type)
                            recommendation = recommendations.get_recommendation(vuln_type)
                            
                            return Vulnerability(
                                vuln_type=vuln_type,
                                severity=severity,
                                description=f"Reflected XSS vulnerability found in form. User input is reflected without proper encoding.",
                                recommendation=recommendation['fix'],
                                evidence={
                                    'url': form_url,
                                    'method': method.upper(),
                                    'parameter': input_name,
                                    'payload': payload,
                                    'form_action': action
                                }
                            )
                    except:
                        continue
        except Exception as e:
            logger.debug(f"Error testing form: {e}")
        
        return None
    
    def _test_url_parameter(self, param_name):
        """Test URL parameter for XSS"""
        try:
            parsed_url = urlparse(self.url)
            params = parse_qs(parsed_url.query)
            
            for payload in self.payloads[:3]:
                # Inject payload
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                # Check if payload is reflected
                if payload in response.text:
                    vuln_type = 'XSS_REFLECTED'
                    severity = severity.get_severity(vuln_type)
                    recommendation = recommendations.get_recommendation(vuln_type)
                    
                    return Vulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        description=f"Reflected XSS vulnerability found in URL parameter '{param_name}'.",
                        recommendation=recommendation['fix'],
                        evidence={
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload
                        }
                    )
        except Exception as e:
            logger.debug(f"Error testing URL parameter: {e}")
        
        return None