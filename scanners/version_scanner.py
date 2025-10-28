import requests
import re
import logging
from bs4 import BeautifulSoup
from models import Vulnerability
from utils import severity
from utils import recommendations
logger = logging.getLogger(__name__)

class VersionScanner:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
    
    def scan(self):
        """Scan for version disclosure and outdated software"""
        vulnerabilities = []
        logger.info(f"Starting version detection scan on {self.url}")
        
        try:
            response = requests.get(
                self.url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            headers = response.headers
            content = response.text
            
            # Check Server header
            if 'Server' in headers:
                server_info = headers['Server']
                
                vuln = Vulnerability(
                    vuln_type='VERSION_DISCLOSURE',
                    severity='LOW',
                    description=f"Server version disclosed: {server_info}",
                    recommendation=recommendations.get_recommendation('VERSION_DISCLOSURE')['fix'],
                    evidence={
                        'server_header': server_info,
                        'url': self.url
                    }
                )
                vulnerabilities.append(vuln)
                
                # Check for outdated versions
                outdated_versions = {
                    'Apache/2.2': 'Apache 2.2 is end-of-life',
                    'Apache/2.0': 'Apache 2.0 is end-of-life',
                    'nginx/1.0': 'Nginx 1.0 is outdated',
                    'nginx/1.1': 'Nginx 1.1 is outdated',
                    'IIS/6.0': 'IIS 6.0 is end-of-life',
                    'IIS/7.0': 'IIS 7.0 is end-of-life'
                }
                
                for version_pattern, message in outdated_versions.items():
                    if version_pattern.lower() in server_info.lower():
                        vuln = Vulnerability(
                            vuln_type='OUTDATED_SOFTWARE',
                            severity='MEDIUM',
                            description=f"{message}: {server_info}",
                            recommendation="Update to the latest stable version of the web server.",
                            evidence={
                                'detected_version': server_info,
                                'url': self.url
                            }
                        )
                        vulnerabilities.append(vuln)
            
            # Check for CMS version disclosure
            soup = BeautifulSoup(content, 'html.parser')
            
            # WordPress detection
            wp_meta = soup.find('meta', {'name': 'generator'})
            if wp_meta and 'WordPress' in wp_meta.get('content', ''):
                wp_version = wp_meta.get('content')
                vuln = Vulnerability(
                    vuln_type='VERSION_DISCLOSURE',
                    severity='LOW',
                    description=f"WordPress version disclosed: {wp_version}",
                    recommendation="Remove version meta tags and update WordPress to the latest version.",
                    evidence={
                        'cms': 'WordPress',
                        'version': wp_version
                    }
                )
                vulnerabilities.append(vuln)
            
            # Check for common CMS paths
            cms_paths = {
                '/wp-admin/': 'WordPress',
                '/administrator/': 'Joomla',
                '/user/login': 'Drupal',
                '/admin/': 'Generic Admin'
            }
            
            for path, cms_name in cms_paths.items():
                try:
                    test_url = self.url.rstrip('/') + path
                    test_response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    if test_response.status_code == 200:
                        vuln = Vulnerability(
                            vuln_type='CMS_DETECTED',
                            severity='LOW',
                            description=f"{cms_name} CMS detected at {path}",
                            recommendation="Ensure CMS is updated and admin panel is protected.",
                            evidence={
                                'cms': cms_name,
                                'admin_path': path,
                                'accessible': True
                            }
                        )
                        vulnerabilities.append(vuln)
                except:
                    continue
            
            # Check for technology disclosure in HTML comments
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            for comment in comments:
                if any(tech in comment.lower() for tech in ['version', 'powered by', 'built with', 'framework']):
                    vuln = Vulnerability(
                        vuln_type='VERSION_DISCLOSURE',
                        severity='LOW',
                        description="Technology information disclosed in HTML comments",
                        recommendation="Remove sensitive information from HTML comments.",
                        evidence={
                            'comment_snippet': comment[:200]
                        }
                    )
                    vulnerabilities.append(vuln)
                    break
            
        except Exception as e:
            logger.error(f"Error during version scan: {e}")
        
        logger.info(f"Version scan completed. Found {len(vulnerabilities)} issues")
        return vulnerabilities