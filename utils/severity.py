class SeverityCalculator:
    @staticmethod
    def get_severity(vuln_type):
        """Get severity level for vulnerability type"""
        severity_map = {
            'SQL_INJECTION': 'CRITICAL',
            'XSS_REFLECTED': 'HIGH',
            'XSS_STORED': 'CRITICAL',
            'EXPOSED_ENV_FILE': 'CRITICAL',
            'EXPOSED_GIT': 'HIGH',
            'EXPOSED_BACKUP': 'HIGH',
            'EXPOSED_CONFIG': 'CRITICAL',
            'EXPOSED_FILE': 'MEDIUM',
            'MISSING_CSP': 'MEDIUM',
            'MISSING_HSTS': 'MEDIUM',
            'MISSING_X_FRAME': 'MEDIUM',
            'MISSING_X_CONTENT_TYPE': 'LOW',
            'MISSING_XSS_PROTECTION': 'LOW',
            'MISSING_REFERRER_POLICY': 'LOW',
            'SSL_EXPIRED': 'CRITICAL',
            'SSL_WEAK_CIPHER': 'HIGH',
            'SSL_WEAK_PROTOCOL': 'HIGH',
            'SSL_SELF_SIGNED': 'MEDIUM',
            'SSL_ERROR': 'HIGH',
            'SSL_EXPIRING_SOON': 'MEDIUM',
            'HTTPS_NOT_ENFORCED': 'MEDIUM',
            'VERSION_DISCLOSURE': 'LOW',
            'OUTDATED_SOFTWARE': 'MEDIUM',
            'DIRECTORY_LISTING': 'MEDIUM',
            'CORS_MISCONFIGURATION': 'HIGH',
            'CMS_DETECTED': 'LOW'
        }
        return severity_map.get(vuln_type, 'MEDIUM')