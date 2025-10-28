from pymongo import MongoClient
from datetime import datetime
from config import Config
import logging

logger = logging.getLogger(__name__)

class Database:
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
        return cls._instance
    
    def connect(self):
        """Connect to MongoDB"""
        try:
            self._client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
            # Test connection
            self._client.server_info()
            self._db = self._client.vuln_scanner
            logger.info("Connected to MongoDB successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self._db = None
            return False
    
    def get_db(self):
        """Get database instance"""
        if self._db is None:
            self.connect()
        return self._db
    
    def save_scan(self, scan_data):
        """Save scan result to database"""
        try:
            if self._db is not None:
                scan_data['created_at'] = datetime.utcnow()
                result = self._db.scans.insert_one(scan_data)
                return str(result.inserted_id)
            return None
        except Exception as e:
            logger.error(f"Error saving scan: {e}")
            return None
    
    def get_scan(self, scan_id):
        """Retrieve scan by ID"""
        try:
            if self._db is not None:
                from bson.objectid import ObjectId
                scan = self._db.scans.find_one({'_id': ObjectId(scan_id)})
                if scan:
                    scan['_id'] = str(scan['_id'])
                    return scan
            return None
        except Exception as e:
            logger.error(f"Error retrieving scan: {e}")
            return None
    
    def get_recent_scans(self, limit=10):
        """Get recent scans"""
        try:
            if self._db is not None:
                scans = list(self._db.scans.find().sort('created_at', -1).limit(limit))
                for scan in scans:
                    scan['_id'] = str(scan['_id'])
                return scans
            return []
        except Exception as e:
            logger.error(f"Error retrieving recent scans: {e}")
            return []

# Initialize database instance
db = Database()