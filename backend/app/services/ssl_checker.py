"""
SSL certificate validation service
"""
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Union
from app.core.logger import setup_logger

logger = setup_logger(__name__)

# Configuration
SSL_TIMEOUT = 5  # seconds
SSL_PORT = 443


def check_ssl(url: str) -> Dict[str, Union[str, int]]:
    """
    Check SSL certificate validity for a URL

    Args:
        url: URL to check SSL certificate for

    Returns:
        Dictionary with status and days_remaining keys
        - status: "Valid" or "Invalid or Expired"
        - days_remaining: Number of days until expiration (0 if invalid)
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    if not hostname:
        logger.error(f"Could not extract hostname from URL: {url}")
        return {"status": "Invalid or Expired", "days_remaining": 0}

    try:
        logger.info(f"Checking SSL certificate for: {hostname}")
        context = ssl.create_default_context()

        # Create a socket connection to the given hostname and port 443 (SSL)
        with socket.create_connection((hostname, SSL_PORT), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract certificate validity dates
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')

        if not not_before or not not_after:
            logger.error(f"Certificate missing validity dates for {hostname}")
            return {"status": "Invalid or Expired", "days_remaining": 0}

        # Convert to datetime objects
        not_before_date = datetime.strptime(
            not_before, "%b %d %H:%M:%S %Y GMT")
        not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")

        # Adjust to UTC timezone
        not_before_date = not_before_date.replace(tzinfo=timezone.utc)
        not_after_date = not_after_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        # Calculate the days remaining
        days_remaining = (not_after_date - now).days

        # Check if certificate is currently valid (not before start date, not after end date)
        if now < not_before_date:
            logger.warning(f"Certificate not yet valid for {hostname}")
            return {"status": "Invalid or Expired", "days_remaining": 0}
        elif days_remaining > 0:
            logger.info(
                f"Valid SSL certificate for {hostname}, {days_remaining} days remaining")
            return {"status": "Valid", "days_remaining": days_remaining}
        else:
            logger.warning(f"Expired SSL certificate for {hostname}")
            return {"status": "Invalid or Expired", "days_remaining": 0}

    except socket.timeout:
        logger.error(f"Timeout checking SSL for {hostname}")
        return {"status": "Invalid or Expired", "days_remaining": 0}
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {hostname}: {e}")
        return {"status": "Invalid or Expired", "days_remaining": 0}
    except ssl.SSLError as e:
        logger.error(f"SSL error for {hostname}: {e}")
        return {"status": "Invalid or Expired", "days_remaining": 0}
    except Exception as e:
        logger.error(f"Unexpected error checking SSL for {hostname}: {e}")
        return {"status": "Invalid or Expired", "days_remaining": 0}
