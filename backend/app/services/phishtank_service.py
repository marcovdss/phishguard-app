"""
PhishTank URL checking service
"""
import requests
import base64
from typing import Dict, Any, Optional
from app.core.logger import setup_logger

logger = setup_logger(__name__)

# Configuration
PHISHTANK_API_URL = "http://checkurl.phishtank.com/checkurl/"
REQUEST_TIMEOUT = 10  # seconds


def check_phishtank(url: str) -> bool:
    """
    Check if URL is flagged in PhishTank database

    Args:
        url: URL to check

    Returns:
        True if URL is malicious, False if safe or unknown
    """
    try:
        logger.info(f"Checking URL with PhishTank: {url}")
        
        # PhishTank expects POST request with url and format
        payload = {
            "url": base64.b64encode(url.encode()).decode(),
            "format": "json"
        }
        
        # User-Agent is required by PhishTank
        headers = {
            "User-Agent": "PhishGuard/1.0"
        }

        response = requests.post(
            PHISHTANK_API_URL, 
            data=payload, 
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            # PhishTank JSON response structure:
            # {
            #     "results": {
            #         "in_database": true/false,
            #         "valid": true/false, (if in_database is true)
            #         ...
            #     }
            # }
            
            results = data.get("results", {})
            in_database = results.get("in_database", False)
            
            if in_database:
                # "valid" means it is a valid phishing site (verified)
                is_valid_phish = results.get("valid", False)
                if is_valid_phish:
                    logger.warning(f"URL flagged as valid phishing by PhishTank: {url}")
                    return True
                else:
                    logger.info(f"URL in PhishTank database but not currently valid phishing: {url}")
                    return False
            else:
                logger.info(f"URL not found in PhishTank database: {url}")
                return False
                
        else:
            logger.error(f"PhishTank API error. Status code: {response.status_code}")
            return False

    except Exception as e:
        logger.error(f"Error checking PhishTank: {e}")
        return False
