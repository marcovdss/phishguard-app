"""
Top-Level Domain (TLD) validation service
"""
from tld import get_tld, is_tld
from app.core.logger import setup_logger

logger = setup_logger(__name__)


def check_tld(url: str) -> bool:
    """
    Validate the Top-Level Domain of a URL

    Args:
        url: URL to validate

    Returns:
        True if TLD is valid, False otherwise
    """
    try:
        # Ensure URL has a scheme (http:// or https://)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        logger.info(f"Checking TLD for URL: {url}")

        # Extract TLD information
        domain_info = get_tld(url, as_object=True)
        tld_str = domain_info.tld

        # Validate TLD
        is_valid = is_tld(tld_str)

        if is_valid:
            logger.info(f"Valid TLD found: {tld_str}")
        else:
            logger.warning(f"Invalid TLD: {tld_str}")

        return is_valid

    except Exception as e:
        logger.error(f"Error checking TLD for {url}: {e}")
        return False
