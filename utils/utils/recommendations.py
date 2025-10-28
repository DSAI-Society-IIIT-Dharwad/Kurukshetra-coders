class RecommendationEngine:
    @staticmethod
    def get_recommendation(vuln_type):
        """Get fix recommendation for vulnerability"""
        recommendations = {
            'SQL_INJECTION': {
                'fix': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
                'code_example': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'resources': ['https://owasp.org/www-community/attacks/SQL_Injection']
            },
            'XSS_REFLECTED': {
                'fix': 'Sanitize and encode all user input before displaying. Use Content Security Policy headers.',
                'code_example': 'import html; safe_input = html.escape(user_input)',
                'resources': ['https://owasp.org/www-community/attacks/xss/']
            },
            'XSS_STORED': {
                'fix': 'Validate and sanitize all input before storing. Encode output when rendering. Implement CSP.',
                'code_example': 'Use libraries like DOMPurify for HTML sanitization',
                'resources': ['https://owasp.org/www-community/attacks/xss/']
            },
            'EXPOSED_ENV_FILE': {
                'fix': 'Add .env to .gitignore and block access via web server configuration.',
                'code_example': '# In .htaccess: <Files .env> Require all denied </Files>',
                'resources': ['https://12factor.net/config']
            },
            'EXPOSED_GIT': {
                'fix': 'Remove .git directory from production or block access via web server.',
                'code_example': '# In nginx: location ~ /\\.git { deny all; }',
                'resources': []
            },
            'EXPOSED_BACKUP': {
                'fix': 'Remove backup files from web root or block access patterns.',
                'code_example': 'Store backups outside the web-accessible directory',
                'resources': []
            },
            'EXPOSED_CONFIG': {
                'fix': 'Remove configuration files from web root or restrict access.',
                'code_example': '# Block access to config files in web server',
                'resources': []
            },
            'EXPOSED_FILE': {
                'fix': 'Remove sensitive files from web root or block public access.',
                'code_example': 'Move files outside public directory or add access restrictions',
                'resources': []
            },
            'MISSING_CSP': {
                'fix': 'Implement Content-Security-Policy header to prevent XSS.',
                'code_example': "Content-Security-Policy: default-src 'self'; script-src 'self'",
                'resources': ['https://content-security-policy.com/']
            },
            'MISSING_HSTS': {
                'fix': 'Add Strict-Transport-Security header to enforce HTTPS.',
                'code_example': 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'resources': []
            },
            'MISSING_X_FRAME': {
                'fix': 'Add X-Frame-Options header to prevent clickjacking.',
                'code_example': 'X-Frame-Options: DENY',
                'resources': []
            },
            'MISSING_X_CONTENT_TYPE': {
                'fix': 'Add X-Content-Type-Options header to prevent MIME sniffing.',
                'code_example': 'X-Content-Type-Options: nosniff',
                'resources': []
            },
            'MISSING_XSS_PROTECTION': {
                'fix': 'Add X-XSS-Protection header for legacy browsers.',
                'code_example': 'X-XSS-Protection: 1; mode=block',
                'resources': []
            },
            'MISSING_REFERRER_POLICY': {
                'fix': 'Add Referrer-Policy header to control referrer information.',
                'code_example': 'Referrer-Policy: strict-origin-when-cross-origin',
                'resources': []
            },
            'SSL_EXPIRED': {
                'fix': 'Renew SSL certificate immediately. Use Let\'s Encrypt for free SSL.',
                'code_example': 'certbot renew',
                'resources': ['https://letsencrypt.org/']
            },
            'SSL_WEAK_CIPHER': {
                'fix': 'Update server configuration to use strong cipher suites only.',
                'code_example': 'Disable SSLv3, TLS 1.0, and TLS 1.1',
                'resources': []
            },
            'SSL_WEAK_PROTOCOL': {
                'fix': 'Disable weak SSL/TLS protocols. Use TLS 1.2 or higher.',
                'code_example': 'Configure server to only allow TLSv1.2 and TLSv1.3',
                'resources': []
            },
            'SSL_SELF_SIGNED': {
                'fix': 'Replace self-signed certificate with a trusted certificate authority certificate.',
                'code_example': 'Use Let\'s Encrypt or purchase from a trusted CA',
                'resources': []
            },
            'SSL_ERROR': {
                'fix': 'Check SSL certificate configuration and validity.',
                'code_example': 'Verify certificate chain and proper installation',
                'resources': []
            },
            'SSL_EXPIRING_SOON': {
                'fix': 'Renew SSL certificate before expiration.',
                'code_example': 'Setup automatic renewal with certbot',
                'resources': []
            },
            'HTTPS_NOT_ENFORCED': {
                'fix': 'Configure server to redirect all HTTP traffic to HTTPS.',
                'code_example': '# Apache: Redirect permanent / https://yourdomain.com/',
                'resources': []
            },
            'VERSION_DISCLOSURE': {
                'fix': 'Configure server to hide version information in headers.',
                'code_example': '# Apache: ServerTokens Prod, ServerSignature Off',
                'resources': []
            },
            'OUTDATED_SOFTWARE': {
                'fix': 'Update software to the latest stable version.',
                'code_example': 'Check for updates and apply security patches',
                'resources': []
            },
            'CMS_DETECTED': {
                'fix': 'Ensure CMS is updated and admin panel is protected.',
                'code_example': 'Use strong passwords, 2FA, and limit login attempts',
                'resources': []
            },
            'DIRECTORY_LISTING': {
                'fix': 'Disable directory listing in web server configuration.',
                'code_example': '# Apache: Options -Indexes',
                'resources': []
            },
            'CORS_MISCONFIGURATION': {
                'fix': 'Configure CORS to allow only trusted domains.',
                'code_example': 'Access-Control-Allow-Origin: https://trusted-domain.com',
                'resources': []
            }
        }
        
        return recommendations.get(vuln_type, {
            'fix': 'Follow security best practices and keep software updated.',
            'code_example': '',
            'resources': ['https://owasp.org/']
        })