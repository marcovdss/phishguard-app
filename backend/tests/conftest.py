"""
Pytest configuration and fixtures
"""
from main import app
import pytest
from fastapi.testclient import TestClient
# from unittest.mock import Mock, patch # Removed unused imports
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def client():
    """FastAPI test client fixture"""
    return TestClient(app)


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables for testing"""
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test_google_key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_virustotal_key")


@pytest.fixture
def sample_url():
    """Sample URL for testing"""
    return "https://example.com"


@pytest.fixture
def sample_malicious_url():
    """Sample malicious URL for testing"""
    return "https://malicious-site.com"


@pytest.fixture
def mock_ssl_valid_response():
    """Mock valid SSL response"""
    return {
        "status": "Valid",
        "days_remaining": 365
    }


@pytest.fixture
def mock_ssl_invalid_response():
    """Mock invalid SSL response"""
    return {
        "status": "Invalid or Expired",
        "days_remaining": 0
    }


@pytest.fixture
def mock_whois_response():
    """Mock WHOIS response"""
    return {
        "Domain Name": "EXAMPLE.COM",
        "Registrar": "Example Registrar Inc.",
        "Creation Date": "1995-08-14 04:00:00",
        "Expiration Date": "2025-08-13 04:00:00",
        "Name Servers": "ns1.example.com, ns2.example.com"
    }
