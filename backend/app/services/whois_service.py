"""
WHOIS information retrieval service
"""
import whois
from datetime import datetime
from typing import Dict, Union, List, Optional
from app.core.logger import setup_logger

logger = setup_logger(__name__)

# Configuration
WHOIS_TIMEOUT = 10  # seconds


def get_whois_info(domain: str) -> Dict[str, str]:
    """
    Retrieve WHOIS registration information for a domain

    Args:
        domain: Domain name to query

    Returns:
        Dictionary containing WHOIS information or error message
    """
    try:
        logger.info(f"Retrieving WHOIS information for: {domain}")
        w = whois.whois(domain)

        def get_first_value(value: Union[str, List, None]) -> Optional[str]:
            """Extract first value from list or return value as-is"""
            if isinstance(value, list) and len(value) > 0:
                return value[0]
            return value

        def format_datetime(value: Union[datetime, str, List, None]) -> str:
            """Format datetime value to string"""
            if isinstance(value, list) and len(value) > 0:
                value = value[0]

            if isinstance(value, datetime):
                return value.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(value, str):
                return value
            return "N/A"

        whois_data = {
            "Domain Name": get_first_value(w.domain_name) or "N/A",
            "Registrar": get_first_value(w.registrar) or "N/A",
            "Creation Date": format_datetime(w.creation_date),
            "Expiration Date": format_datetime(w.expiration_date),
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "N/A"
        }

        logger.info(f"Successfully retrieved WHOIS data for {domain}")
        return whois_data

    except Exception as e:
        logger.error(f"Error retrieving WHOIS information for {domain}: {e}")
        return {
            "error": f"Error retrieving WHOIS information: {str(e)}"
        }
