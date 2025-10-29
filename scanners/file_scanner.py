import requests
import logging
from models import Vulnerability
from utils.severity import SeverityCalculator
from utils.recommendations import RecommendationEngine

logger = logging.getLogger(__name__)

class FileScanner:
    def __init__(self, url, timeout=10):
        self.url = url.rstrip('/')
        self.timeout = timeout
        
        # Common sensitive files and directories
        self.sensitive_files = [
            '.env',
            '.env.local',
            '.env.production',
            '.git/config',
            '.git/HEAD',
            '.gitignore',
            'config.php',
            'configuration.php',
            'wp-config.php',
            'web.config',
            'database.yml',
            'settings.py',
            '.htaccess',
            '.htpasswd',
            'phpinfo.php',
            'info.php',
            'test.php',
            'admin/',
            'backup/',
            'backups/',
            'db_backup.sql',
            'backup.sql',
            'database.sql',
            'dump.sql',
            'config.inc.php',
            'config.php.bak',
            'config.php~',
            'configuration.php.bak',
            'wp-config.php.bak',
            '.DS_Store',
            'composer.json',
            'package.json',
            '.npmrc',
            'Dockerfile',
            'docker-compose.yml',
            '.dockerignore',
            'README.md',
            'LICENSE',
            'robots.txt',
            'sitemap.xml',
            'crossdomain.xml',
            'phpMyAdmin/',
            'pma/',
            'adminer.php',
            'server-status',
            'server-info',
            '.svn/entries',
            'CVS/Entries'
        ]
    
    def scan(self):
        """Scan for exposed sensitive files"""
        vulnerabilities = []
        logger.info(f"Starting file exposure scan on {self.url}")
        
        for file_path in self.sensitive_files:
            try:
                test_url = f"{self.url}/{file_path}"
                
                response = requests.get(
                    test_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Check if file is accessible
                if response.status_code == 200:
                    # Determine vulnerability type
                    vuln_type = self._get_vuln_type(file_path)
                    severity = severity.get_severity(vuln_type)
                    recommendation = RecommendationEngine.get_recommendation(vuln_type)
                    
                    vuln = Vulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        description=f"Sensitive file '{file_path}' is publicly accessible.",
                        recommendation=recommendation['fix'],
                        evidence={
                            'url': test_url,
                            'status_code': response.status_code,
                            'file': file_path,
                            'content_length': len(response.content)
                        }
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Exposed file found: {test_url}")
                
                # Check for directory listing
                elif response.status_code == 200 and 'Index of' in response.text:
                    vuln = Vulnerability(
                        vuln_type='DIRECTORY_LISTING',
                        severity='MEDIUM',
                        description=f"Directory listing enabled at '{file_path}'.",
                        recommendation="Disable directory listing in web server configuration.",
                        evidence={
                            'url': test_url,
                            'status_code': response.status_code
                        }
                    )
                    vulnerabilities.append(vuln)
                    logger.warning(f"Directory listing found: {test_url}")
                
            except requests.RequestException:
                continue
            except Exception as e:
                logger.error(f"Error checking {file_path}: {e}")
                continue
        
        logger.info(f"File scan completed. Found {len(vulnerabilities)} exposed files")
        return vulnerabilities
    
    def _get_vuln_type(self, file_path):
        """Determine vulnerability type based on file"""
        if '.env' in file_path:
            return 'EXPOSED_ENV_FILE'
        elif '.git' in file_path:
            return 'EXPOSED_GIT'
        elif any(x in file_path for x in ['backup', '.bak', '.sql', 'dump']):
            return 'EXPOSED_BACKUP'
        elif any(x in file_path for x in ['config', 'configuration', 'settings']):
            return 'EXPOSED_CONFIG'
        else:
            return 'EXPOSED_FILE'