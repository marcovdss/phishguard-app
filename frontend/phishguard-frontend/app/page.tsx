"use client";
import { useState } from "react";
import axios from "axios";
import VerificationResults from "./components/VerificationResults";

// Define the interface for verification results
interface VerificationResult {
  google_safe_browsing: string;
  virustotal: string;
  ssl: string;
  ssl_days_remaining: number;
  tld: string;
  whois?: Record<string, string>;
}

export default function Home() {
  const [url, setUrl] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerificationResult | null>(null);

  // API URL, with fallback to localhost if not defined
  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

  const handleSubmit = async () => {
    if (!url) {
      setError("Please enter a URL.");
      return;
    }

    setError(null);
    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/verify-url`, { url });
      setResult(response.data);
    } catch (err) {
      setError("An error occurred while verifying the URL.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleSubmit();
    }
  };

  // Check if results exist for conditional rendering
  const hasResults =
    result?.google_safe_browsing ||
    result?.virustotal ||
    result?.ssl ||
    result?.whois;

  return (
    <div className={`container ${hasResults ? "with-results" : "without-results"}`}>
      <div className="form-container">
        <h1 className="heading">
          PhishGuard - <span className="subheading">URL Verifier</span>
        </h1>

        <div className="input-container">
          <input
            type="text"
            placeholder="Enter URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={handleKeyDown} // Handle 'Enter' key press
            className="input-field"
          />
        </div>

        <div className="button-container">
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="submit-button"
          >
            {loading ? "Verifying..." : "Verify URL"}
          </button>
        </div>

        {error && <p className="error-message">{error}</p>}
      </div>

      {hasResults && (
        <div className="results-container">
          <VerificationResults result={result} />
        </div>
      )}
    </div>
  );
}
