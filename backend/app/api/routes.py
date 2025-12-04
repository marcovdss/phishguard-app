"""
API routes for URL verification
"""
from fastapi import APIRouter, HTTPException
from app.models.schemas import URLRequest, VerificationResponse
from app.services.blacklist import check_blacklist, check_virustotal
from app.services.ssl_checker import check_ssl
from app.services.whois_service import get_whois_info
from app.services.phishtank_service import check_phishtank
from app.services.tld_checker import check_tld
from app.core.utils import validate_url, normalize_url
from app.core.logger import setup_logger
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

router = APIRouter()
logger = setup_logger(__name__)
from app.core.limiter import limiter


@router.post("/verify-url", response_model=VerificationResponse)
@limiter.limit("10/minute")
async def verify_url(request: Request, url_request: URLRequest):
    """
    Verify a URL against multiple security services

    Args:
        request: The request object (needed for rate limiting)
        url_request: URLRequest containing the URL to verify

    Returns:
        VerificationResponse with results from all security checks

    Raises:
        HTTPException: If URL is invalid
    """
    return await process_verification(url_request)


@router.get("/verify-url", response_model=VerificationResponse)
async def verify_url_get(url: str):
    """
    Verify a URL via GET request (convenience endpoint)

    Args:
        url: URL to verify (query parameter)

    Returns:
        VerificationResponse with results from all security checks
    """
    request_data = URLRequest(url=url)
    return await process_verification(request_data)


async def process_verification(url_request: URLRequest):
    url = url_request.url.strip()

    # Validate URL format
    is_valid, error_message = validate_url(url)
    if not is_valid:
        logger.warning(f"Invalid URL submitted: {url} - {error_message}")
        raise HTTPException(status_code=400, detail=error_message)

    # Normalize URL
    normalized_url = normalize_url(url)
    logger.info(f"Starting verification for URL: {normalized_url}")

    # Initialize result with default values
    result = {
        "google_safe_browsing": "Safe",
        "virustotal": "Safe",
        "ssl": "Invalid or Expired",
        "ssl_days_remaining": None,
        "tld": "Invalid",
        "whois": None,
    }

    # Check Google Safe Browsing
    try:
        if check_blacklist(normalized_url):
            result["google_safe_browsing"] = "Malicious"
    except ValueError as e:
        # API key not configured
        logger.warning(f"Google Safe Browsing check skipped: {e}")
        result["google_safe_browsing"] = "Error"
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing: {e}")
        result["google_safe_browsing"] = "Error"

    # Check VirusTotal
    try:
        if check_virustotal(normalized_url):
            result["virustotal"] = "Malicious"
    except ValueError as e:
        # API key not configured
        logger.warning(f"VirusTotal check skipped: {e}")
        result["virustotal"] = "Error"
    except Exception as e:
        logger.error(f"Error checking VirusTotal: {e}")
        result["virustotal"] = "Error"

    # Check SSL certificate
    try:
        ssl_info = check_ssl(normalized_url)
        if ssl_info:
            result["ssl"] = ssl_info.get("status", "Invalid or Expired")
            result["ssl_days_remaining"] = ssl_info.get("days_remaining")
    except Exception as e:
        logger.error(f"Error checking SSL: {e}")

    # Check TLD validity
    try:
        if check_tld(normalized_url):
            result["tld"] = "Valid"
    except Exception as e:
        logger.error(f"Error checking TLD: {e}")

    # Get WHOIS information
    try:
        whois_info = get_whois_info(normalized_url)
        if whois_info and "error" not in whois_info:
            result["whois"] = whois_info
    except Exception as e:
        logger.error(f"Error getting WHOIS info: {e}")

    # Check PhishTank
    try:
        if check_phishtank(normalized_url):
            result["phishtank"] = "Malicious"
        else:
            result["phishtank"] = "Safe"
    except Exception as e:
        logger.error(f"Error checking PhishTank: {e}")
        result["phishtank"] = "Error"

    logger.info(f"Verification completed for URL: {normalized_url}")
    return result
