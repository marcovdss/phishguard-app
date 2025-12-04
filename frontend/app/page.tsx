"use client";
import { useState } from "react";
import { PhishGuardAPI } from "./lib/api";
import { VerificationResult } from "./types";
import VerificationResults from "./components/VerificationResults";
import "./styles/globals.css";

export default function Home() {
  const [url, setUrl] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerificationResult | null>(null);

  const handleSubmit = async () => {
    if (!url) {
      setError("Please enter a URL.");
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await PhishGuardAPI.verifyURL(url);
      setResult(data);
    } catch (err) {
      setError("An error occurred while verifying the URL. Please try again.");
      console.error("Verification error:", err);
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
