@echo off
echo Starting Vulnerability Scanner Backend Setup...

REM Create virtual environment
python -m venv venv

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
pip install -r requirements.txt

REM Create .env if doesn't exist
if not exist .env (
    echo FLASK_ENV=development > .env
    echo FLASK_DEBUG=True >> .env
    echo PORT=5000 >> .env
    echo MONGO_URI=mongodb://localhost:27017/vuln_scanner >> .env
    echo SECRET_KEY=change-this-secret-key-in-production >> .env
    echo MAX_SCAN_TIMEOUT=30 >> .env
    echo Created .env file
)

echo Setup complete!
echo.
echo To start the server, run:
echo   venv\Scripts\activate
echo   python app.py
echo.
echo API will be available at: http://localhost:5000
pause


---

## **FINAL PROJECT STRUCTURE**

Your final backend folder should look like this:

backend/
├── venv/                      # Virtual environment (created after setup)
├── app.py                     # Main Flask application ✅
├── config.py                  # Configuration ✅
├── database.py                # Database connection ✅
├── models.py                  # Data models ✅
├── requirements.txt           # Dependencies ✅
├── .env                       # Environment variables ✅
├── README.md                  # Documentation ✅
├── quick_start.sh            # Quick setup script (Mac/Linux) ✅
├── quick_start.bat           # Quick setup script (Windows) ✅
├── scanners/
│   ├── _init_.py           ✅
│   ├── sql_injection.py      ✅
│   ├── xss_scanner.py        ✅
│   ├── file_scanner.py       ✅
│   ├── header_scanner.py     ✅
│   ├── ssl_scanner.py        ✅
│   └── version_scanner.py    ✅
└── utils/
    ├── _init_.py           ✅
    ├── severity.py           ✅
    ├── recommendations.py    ✅
    └── report_generator.py   ✅