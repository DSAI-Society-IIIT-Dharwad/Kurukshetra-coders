from datetime import datetime
from typing import List, Dict

class Vulnerability:
    def __init__(self, vuln_type, severity, description, recommendation, evidence=None):
        self.type = vuln_type
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.evidence = evidence or {}
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self):
        return {
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'timestamp': self.timestamp
        }

class ScanResult:
    def __init__(self, url, scan_id=None):
        self.scan_id = scan_id
        self.url = url
        self.vulnerabilities = []
        self.scan_start = datetime.utcnow()
        self.scan_end = None
        self.total_checks = 0
        self.status = 'in_progress'
        self.error = None
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        self.vulnerabilities.append(vulnerability)
    
    def complete_scan(self):
        self.scan_end = datetime.utcnow()
        self.status = 'completed'
        self.total_checks = len(self.vulnerabilities)
    
    def fail_scan(self, error_message):
        self.scan_end = datetime.utcnow()
        self.status = 'failed'
        self.error = error_message
    
    def calculate_security_score(self):
        """Calculate security score (0-100)"""
        if not self.vulnerabilities:
            return 100
        
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3
        }
        
        total_deduction = sum(
            severity_weights.get(v.severity, 0) 
            for v in self.vulnerabilities
        )
        
        score = max(0, 100 - total_deduction)
        return score
    
    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'url': self.url,
            'status': self.status,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'total_vulnerabilities': len(self.vulnerabilities),
            'security_score': self.calculate_security_score(),
            'scan_start': self.scan_start.isoformat(),
            'scan_end': self.scan_end.isoformat() if self.scan_end else None,
            'error': self.error,
            'severity_breakdown': self.get_severity_breakdown()
        }
    
    def get_severity_breakdown(self):
        """Get count of vulnerabilities by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            if vuln.severity in breakdown:
                breakdown[vuln.severity] += 1
        return breakdown