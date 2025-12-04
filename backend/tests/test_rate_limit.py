import pytest
from unittest.mock import patch

@pytest.mark.integration
def test_rate_limiting(client, sample_url):
    """Test that rate limiting works for verify-url endpoint"""
    # Mock services to return quickly
    with patch('app.api.routes.check_blacklist', return_value=False), \
         patch('app.api.routes.check_virustotal', return_value=False), \
         patch('app.api.routes.check_ssl', return_value={"status": "Valid", "days_remaining": 365}), \
         patch('app.api.routes.check_tld', return_value=True), \
         patch('app.api.routes.get_whois_info', return_value={}):

        # Make 10 allowed requests
        for i in range(10):
            response = client.post("/verify-url", json={"url": sample_url})
            assert response.status_code == 200, f"Request {i+1} failed"

        # The 11th request should be rate limited
        response = client.post("/verify-url", json={"url": sample_url})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.text or "Too Many Requests" in response.text
