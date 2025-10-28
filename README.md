# Vulnerability Scanner - Backend

## Setup Instructions

### 1. Install Python (if not installed)
Download Python 3.8+ from https://www.python.org/downloads/

### 2. Create Virtual Environment
bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Mac/Linux:
source venv/bin/activate


### 3. Install Dependencies
bash
pip install -r requirements.txt


### 4. Setup MongoDB (Optional - for database features)

*Option A: Local MongoDB*
- Download from https://www.mongodb.com/try/download/community
- Install and start MongoDB service

*Option B: MongoDB Atlas (Cloud - FREE)*
- Go to https://www.mongodb.com/cloud/atlas
- Create free account
- Create cluster
- Get connection string
- Update MONGO_URI in .env file

*Option C: Skip Database (Works without it)*
- The app will work without MongoDB
- Recent scans won't be saved

### 5. Run the Application
bash
python app.py


The API will start on http://localhost:5000

## API Endpoints

### 1. Start a Scan
bash
POST http://localhost:5000/api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}


### 2. Get Scan Results
bash
GET http://localhost:5000/api/scan/{scan_id}


### 3. Download PDF Report
bash
GET http://localhost:5000/api/report/{scan_id}


### 4. Get Recent Scans
bash
GET http://localhost:5000/api/scans?limit=10


### 5. Health Check
bash
GET http://localhost:5000/api/health


## Testing the API

### Using cURL:
bash
# Start a scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://testphp.vulnweb.com"}'

# Get results (replace SCAN_ID with actual ID from above)
curl http://localhost:5000/api/scan/SCAN_ID


### Using Postman:
1. Import the API endpoints
2. Create POST request to /api/scan
3. Add JSON body: {"url": "http://testphp.vulnweb.com"}
4. Send request and copy scan_id
5. Create GET request to /api/scan/{scan_id}

## Test URLs (Safe to Scan)

These are intentionally vulnerable test sites:

1. http://testphp.vulnweb.com
2. http://demo.testfire.net
3. http://zero.webappsecurity.com

*IMPORTANT:* Only scan websites you have permission to test!

## Deployment

### Deploy to Render.com (FREE)

1. Push code to GitHub
2. Go to https://render.com
3. Create new Web Service
4. Connect GitHub repo
5. Build Command: pip install -r requirements.txt
6. Start Command: python app.py
7. Add environment variables from .env file
8. Deploy!

### Deploy to Railway.app (FREE)

1. Push code to GitHub
2. Go to https://railway.app
3. New Project → Deploy from GitHub
4. Select repository
5. Add environment variables
6. Deploy!

## Troubleshooting

### Port Already in Use
Change port in .env file or:
bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Mac/Linux
lsof -ti:5000 | xargs kill


### SSL Certificate Errors
The scanners use verify=False for testing. This is intentional for the hackathon but should be removed in production.

### MongoDB Connection Failed
The app will continue to work without MongoDB. Active scans are stored in memory.

## Security Note

⚠ This tool is for educational and authorized security testing only. Never scan websites without explicit permission from the owner.