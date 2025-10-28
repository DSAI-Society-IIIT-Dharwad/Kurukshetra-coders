import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/vuln_scanner')
    MAX_SCAN_TIMEOUT = int(os.getenv('MAX_SCAN_TIMEOUT', 30))
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'
    
    # Scan configuration
    MAX_RETRIES = 3
    REQUEST_TIMEOUT = 10
    USER_AGENT = 'VulnScanner/1.0 (Security Research Tool)'