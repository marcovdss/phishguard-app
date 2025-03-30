import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from checker.blacklist import check_blacklist, check_virustotal
from checker.check_ssl import check_ssl
from checker.whois_lookup import get_whois_info
from checker.check_tld import check_tld

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo Pydantic para entrada de dados
class URLRequest(BaseModel):
    url: str

# Endpoint POST utilizando Pydantic para validar o corpo da requisição
@app.post("/verify-url")
async def verify_url(request: URLRequest):
    url = request.url

    result = {
        "google_safe_browsing": "Malicious" if check_blacklist(url) else "Safe",
        "virustotal": "Malicious" if check_virustotal(url) else "Safe",
        "ssl": "Invalid or Expired",
        "ssl_days_remaining": None,
        "tld": "Invalid",
        "whois": None,
    }

    # Verifica SSL
    ssl_info = check_ssl(url)
    if ssl_info:
        result["ssl"] = ssl_info.get("status", "Invalid or Expired")
        result["ssl_days_remaining"] = ssl_info.get("days_remaining")

    # Verifica TLD
    if check_tld(url):
        result["tld"] = "Valid"

    # Obtém informações WHOIS
    whois_info = get_whois_info(url)
    if whois_info and "error" not in whois_info:
        result["whois"] = whois_info

    return result

# Endpoint GET para facilitar requisições via query params
@app.get("/verify-url")
async def verify_url_get(url: str):
    request_data = URLRequest(url=url)
    return await verify_url(request_data)
