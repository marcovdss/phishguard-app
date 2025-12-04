from pydantic import BaseModel
from typing import Optional, Dict


class URLRequest(BaseModel):
    """Request model for URL verification"""
    url: str


class VerificationResponse(BaseModel):
    """Response model for URL verification results"""
    google_safe_browsing: str
    virustotal: str
    ssl: str
    ssl_days_remaining: Optional[int]
    tld: str
    phishtank: Optional[str] = None
    whois: Optional[Dict[str, str]]
