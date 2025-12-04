"""
Blacklist checking services for Google Safe Browsing and VirusTotal
"""
import requests
import os
import base64
from dotenv import load_dotenv
# from typing import Optional # Removed unused import
from app.core.logger import setup_logger

# Load environment variables from .env file
load_dotenv()

logger = setup_logger(__name__)

# Configuration
REQUEST_TIMEOUT = 10  # seconds
MAX_RETRIES = 2


def check_blacklist(url: str) -> bool:
    """
    Check if URL is in Google Safe Browsing blacklist

    Args:
        url: URL to check

    Returns:
        True if URL is malicious, False if safe

    Raises:
        ValueError: If API key is not configured
        requests.RequestException: If API request fails
    """
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        logger.warning(
            "Google Safe Browsing API key not found in environment variables")
        raise ValueError("Google Safe Browsing API key not configured")

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(
                f"Checking URL with Google Safe Browsing: {url} (attempt {attempt + 1}/{MAX_RETRIES})")
            response = requests.post(
                api_url, json=payload, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()

            result = response.json()
            is_malicious = result.get("matches") is not None

            if is_malicious:
                logger.warning(
                    f"URL flagged as malicious by Google Safe Browsing: {url}")
            else:
                logger.info(
                    f"URL marked as safe by Google Safe Browsing: {url}")

            return is_malicious

        except requests.Timeout:
            logger.error(
                f"Timeout checking Google Safe Browsing (attempt {attempt + 1}/{MAX_RETRIES})")
            if attempt == MAX_RETRIES - 1:
                raise
        except requests.RequestException as e:
            logger.error(f"Error checking Google Safe Browsing: {e}")
            if attempt == MAX_RETRIES - 1:
                raise

    return False


def check_virustotal(url: str) -> bool:
    """
    Check if URL is flagged in VirusTotal database

    Args:
        url: URL to check

    Returns:
        True if URL is malicious, False if safe

    Raises:
        ValueError: If API key is not configured
        requests.RequestException: If API request fails
    """
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.warning("VirusTotal API key not found in environment variables")
        raise ValueError("VirusTotal API key not configured")

    url_encoded = base64.urlsafe_b64encode(
        url.encode('utf-8')).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_encoded}"

    headers = {
        "x-apikey": api_key
    }

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(
                f"Checking URL with VirusTotal: {url} (attempt {attempt + 1}/{MAX_RETRIES})")
            response = requests.get(
                api_url, headers=headers, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "attributes" in data["data"]:
                    attributes = data["data"]["attributes"]
                    stats = attributes.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)

                    if malicious_count > 0:
                        logger.warning(
                            f"URL flagged by {malicious_count} VirusTotal engines: {url}")
                        return True
                    else:
                        logger.info(f"URL marked as safe by VirusTotal: {url}")
                        return False

            elif response.status_code == 404:
                # URL not found in VirusTotal database - treat as safe
                logger.info(f"URL not found in VirusTotal database: {url}")
                return False
            else:
                logger.error(
                    f"VirusTotal API error. Status code: {response.status_code}")
                response.raise_for_status()

        except requests.Timeout:
            logger.error(
                f"Timeout checking VirusTotal (attempt {attempt + 1}/{MAX_RETRIES})")
            if attempt == MAX_RETRIES - 1:
                raise
        except requests.RequestException as e:
            logger.error(f"Error checking VirusTotal: {e}")
            if attempt == MAX_RETRIES - 1:
                raise

    return False
