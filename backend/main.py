import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from checker.blacklist import check_blacklist, check_virustotal
from checker.check_ssl import check_ssl
from checker.whois_lookup import get_whois_info
from checker.check_tld import check_tld
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (or specify specific ones)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

class URLRequest(BaseModel):
    url: str

@app.post("/verify-url")
@app.get("/verify-url")  # Added GET method to handle query params
async def verify_url(request: URLRequest = None, url: str = None):
    if not request and not url:
        raise HTTPException(status_code=400, detail="URL parameter is required.")
    
    url = request.url if request else url  # Fallback to query parameter if no body

    result = {}

    # Check Google Safe Browsing
    result["google_safe_browsing"] = "Malicious" if check_blacklist(url) else "Safe"

    # Check VirusTotal
    result["virustotal"] = "Malicious" if check_virustotal(url) else "Safe"

    # Check SSL and return status along with days remaining
    ssl_info = check_ssl(url)
    result["ssl"] = ssl_info["status"]  # Simplified status ("Valid" or "Invalid or Expired")
    result["ssl_days_remaining"] = ssl_info["days_remaining"]  # Number of days remaining

    # Check TLD
    tld_valid = check_tld(url)
    result["tld"] = "Valid" if tld_valid else "Invalid"

    # Get WHOIS info
    whois_info = get_whois_info(url)
    result["whois"] = whois_info if "error" not in whois_info else None

    return result
