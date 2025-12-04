"""
Utility functions for URL validation and normalization
"""
import re
from urllib.parse import urlparse
from typing import Tuple


def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding scheme if missing and removing trailing slashes

    Args:
        url: URL to normalize

    Returns:
        Normalized URL string
    """
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]

    return url


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate if a string is a valid URL

    Args:
        url: URL string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url or not url.strip():
        return False, "URL cannot be empty"

    url = url.strip()

    # Check minimum length
    if len(url) < 3:
        return False, "URL is too short"

    # Check maximum length
    if len(url) > 2048:
        return False, "URL is too long"

    # Add scheme if missing for validation
    test_url = url if url.startswith(
        ('http://', 'https://')) else 'https://' + url

    try:
        parsed = urlparse(test_url)

        # Must have a netloc (domain)
        if not parsed.netloc:
            return False, "Invalid URL format: missing domain"

        # Check for valid domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'  # noqa: E501
        hostname = parsed.netloc.split(':')[0]  # Remove port if present

        if not re.match(domain_pattern, hostname):
            return False, "Invalid domain format"

        return True, ""

    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def extract_domain(url: str) -> str:
    """
    Extract the domain from a URL

    Args:
        url: URL to extract domain from

    Returns:
        Domain string
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc

    # Remove port if present
    if ':' in hostname:
        hostname = hostname.split(':')[0]

    return hostname
