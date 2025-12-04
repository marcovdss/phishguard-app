"""
Tests for API routes
"""
import pytest
from unittest.mock import patch


@pytest.mark.unit
def test_root_endpoint(client):
    """Test root endpoint returns correct information"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "PhishGuard API"
    assert data["version"] == "1.0.0"
    assert data["docs"] == "/docs"


@pytest.mark.unit
def test_health_check(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.unit
def test_verify_url_invalid_empty(client):
    """Test URL verification with empty URL"""
    response = client.post("/verify-url", json={"url": ""})
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


@pytest.mark.unit
def test_verify_url_invalid_format(client):
    """Test URL verification with invalid format"""
    response = client.post("/verify-url", json={"url": "not a valid url"})
    assert response.status_code == 400


@pytest.mark.unit
def test_verify_url_too_long(client):
    """Test URL verification with too long URL"""
    long_url = "https://" + "a" * 3000 + ".com"
    response = client.post("/verify-url", json={"url": long_url})
    assert response.status_code == 400
    assert "too long" in response.json()["detail"].lower()


@pytest.mark.integration
@patch('app.api.routes.check_blacklist')
@patch('app.api.routes.check_virustotal')
@patch('app.api.routes.check_ssl')
@patch('app.api.routes.check_tld')
@patch('app.api.routes.get_whois_info')
def test_verify_url_safe(mock_whois, mock_tld, mock_ssl, mock_vt, mock_gsb,
                         client, sample_url, mock_ssl_valid_response, mock_whois_response):
    """Test URL verification with safe URL"""
    # Mock all services to return safe results
    mock_gsb.return_value = False
    mock_vt.return_value = False
    mock_ssl.return_value = mock_ssl_valid_response
    mock_tld.return_value = True
    mock_whois.return_value = mock_whois_response

    response = client.post("/verify-url", json={"url": sample_url})
    assert response.status_code == 200

    data = response.json()
    assert data["google_safe_browsing"] == "Safe"
    assert data["virustotal"] == "Safe"
    assert data["ssl"] == "Valid"
    assert data["ssl_days_remaining"] == 365
    assert data["tld"] == "Valid"
    assert data["whois"] is not None


@pytest.mark.integration
@patch('app.api.routes.check_blacklist')
@patch('app.api.routes.check_virustotal')
@patch('app.api.routes.check_ssl')
@patch('app.api.routes.check_tld')
@patch('app.api.routes.get_whois_info')
def test_verify_url_malicious(mock_whois, mock_tld, mock_ssl, mock_vt, mock_gsb,
                              client, sample_malicious_url):
    """Test URL verification with malicious URL"""
    # Mock services to return malicious results
    mock_gsb.return_value = True
    mock_vt.return_value = True
    mock_ssl.return_value = {
        "status": "Invalid or Expired", "days_remaining": 0}
    mock_tld.return_value = False
    mock_whois.return_value = {"error": "Domain not found"}

    response = client.post("/verify-url", json={"url": sample_malicious_url})
    assert response.status_code == 200

    data = response.json()
    assert data["google_safe_browsing"] == "Malicious"
    assert data["virustotal"] == "Malicious"


@pytest.mark.integration
@patch('app.api.routes.check_blacklist')
@patch('app.api.routes.check_virustotal')
@patch('app.api.routes.check_ssl')
@patch('app.api.routes.check_tld')
@patch('app.api.routes.get_whois_info')
def test_verify_url_api_errors(mock_whois, mock_tld, mock_ssl, mock_vt, mock_gsb,
                               client, sample_url):
    """Test URL verification when APIs return errors"""
    # Mock services to raise exceptions
    mock_gsb.side_effect = ValueError("API key not configured")
    mock_vt.side_effect = ValueError("API key not configured")
    mock_ssl.return_value = {
        "status": "Invalid or Expired", "days_remaining": 0}
    mock_tld.return_value = True
    mock_whois.return_value = {"error": "WHOIS lookup failed"}

    response = client.post("/verify-url", json={"url": sample_url})
    assert response.status_code == 200

    data = response.json()
    assert data["google_safe_browsing"] == "Error"
    assert data["virustotal"] == "Error"


@pytest.mark.unit
def test_verify_url_get_endpoint(client):
    """Test GET endpoint for URL verification"""
    with patch('app.api.routes.check_blacklist', return_value=False), \
            patch('app.api.routes.check_virustotal', return_value=False), \
            patch('app.api.routes.check_ssl', return_value={"status": "Valid", "days_remaining": 365}), \
            patch('app.api.routes.check_tld', return_value=True), \
            patch('app.api.routes.get_whois_info', return_value={}):

        response = client.get("/verify-url?url=https://example.com")
        assert response.status_code == 200
        data = response.json()
        assert "google_safe_browsing" in data
