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
    setResult(null); // Clear previous results

    try {
      const response = await axios.post(`${API_URL}/verify-url`, { url });
      setResult(response.data);
    } catch (err) {
      setError("An error occurred while verifying the URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleSubmit();
    }
  };

  return (
    <main className="container">
      <div className="text-center mt-10">
        <h1>PhishGuard</h1>
        <p className="subtitle">
          Advanced real-time URL verification and threat intelligence.
          Protect yourself from phishing and malicious websites.
        </p>
      </div>

      <div className="search-box">
        <input
          type="text"
          placeholder="Enter URL to verify (e.g., google.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          className={`input-field ${loading ? 'loading-pulse' : ''}`}
          disabled={loading}
        />
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="submit-button"
        >
          {loading ? "Scanning..." : "Verify"}
        </button>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: '1rem', color: 'var(--error)', borderRadius: 'var(--radius-sm)' }}>
          ⚠️ {error}
        </div>
      )}

      {result && (
        <VerificationResults result={result} />
      )}
    </main>
  );
}
