import React from 'react';
import { VerificationResult } from '../types';

interface VerificationResultsProps {
  result: VerificationResult;
}

const VerificationResults: React.FC<VerificationResultsProps> = ({ result }) => {
  const getStatusClass = (status: string) => {
    if (status === "Safe" || status === "Valid") return "status-safe";
    if (status === "Warning") return "status-warning";
    return "status-danger";
  };

  return (
    <div className="w-full">
      <div className="results-grid">
        {/* Google Safe Browsing */}
        <div className="glass-panel result-card">
          <div className="card-header">
            <span className="card-title">Google Safe Browsing</span>
            <span className={`status-badge ${getStatusClass(result.google_safe_browsing)}`}>
              {result.google_safe_browsing}
            </span>
          </div>
          <p className="text-sm text-gray-400">Checks URL against Google&apos;s blacklist.</p>
        </div>

        {/* VirusTotal */}
        <div className="glass-panel result-card">
          <div className="card-header">
            <span className="card-title">VirusTotal Analysis</span>
            <span className={`status-badge ${getStatusClass(result.virustotal)}`}>
              {result.virustotal}
            </span>
          </div>
          <p className="text-sm text-gray-400">Aggregated antivirus engine results.</p>
        </div>

        {/* SSL Certificate */}
        <div className="glass-panel result-card">
          <div className="card-header">
            <span className="card-title">SSL Security</span>
            <span className={`status-badge ${getStatusClass(result.ssl)}`}>
              {result.ssl}
            </span>
          </div>
          {result.ssl_days_remaining ? (
            <div className="mt-2">
              <span className="text-2xl font-bold">{result.ssl_days_remaining}</span>
              <span className="text-sm text-gray-400 ml-2">days remaining</span>
            </div>
          ) : (
            <p className="text-sm text-red-400 mt-2">Certificate invalid or missing</p>
          )}
        </div>

        {/* TLD Validation */}
        <div className="glass-panel result-card">
          <div className="card-header">
            <span className="card-title">Domain Extension</span>
            <span className={`status-badge ${getStatusClass(result.tld)}`}>
              {result.tld}
            </span>
          </div>
          <p className="text-sm text-gray-400">Top-Level Domain validity check.</p>
        </div>
      </div>

      {/* WHOIS Info */}
      {result.whois && (
        <div className="glass-panel result-card whois-section">
          <div className="card-header">
            <span className="card-title">WHOIS Registration Data</span>
          </div>
          <div className="whois-grid">
            {Object.entries(result.whois).map(([key, value]) => (
              <div key={key} className="whois-item">
                <span className="whois-label">{key.replace(/_/g, ' ').toUpperCase()}</span>
                <span className="whois-value">{String(value)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default VerificationResults;
