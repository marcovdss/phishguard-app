interface VerificationResultsProps {
  result: {
    google_safe_browsing: string;
    virustotal: string;
    ssl: string;
    ssl_days_remaining: number;
    tld: string;
    whois?: Record<string, string>;
  };
}

const VerificationResults: React.FC<VerificationResultsProps> = ({ result }) => {
  return (
    <div>
      <h2>Verification Results</h2>
      <div>
        {/* Google Safe Browsing result */}
        <div
          className={`result-item ${
            result.google_safe_browsing === "Safe"
              ? "success"
              : result.google_safe_browsing === "Warning"
              ? "warning"
              : "error"
          }`}
        >
          <strong>Google Safe Browsing:</strong> {result.google_safe_browsing}
        </div>

        {/* VirusTotal result */}
        <div
          className={`result-item ${
            result.virustotal === "Safe"
              ? "success"
              : result.virustotal === "Warning"
              ? "warning"
              : "error"
          }`}
        >
          <strong>VirusTotal:</strong> {result.virustotal}
        </div>

        {/* TLD Validation result */}
        <div
          className={`result-item ${
            result.tld === "Valid"
              ? "success"
              : result.tld === "Warning"
              ? "warning"
              : "error"
          }`}
        >
          <strong>TLD Validation:</strong> {result.tld}
        </div>

        {/* SSL Certificate result */}
        <div
          className={`result-item ${
            result.ssl === "Valid"
              ? "success"
              : result.ssl === "Warning"
              ? "warning"
              : "error"
          }`}
        >
          <strong>SSL Certificate:</strong> {result.ssl}
          <p><strong>Days Remaining:</strong> {result.ssl_days_remaining} days</p>
        </div>

        {/* Display WHOIS info if available */}
        {result.whois && (
          <div className="result-item whois">
            <h3>WHOIS Info:</h3>
            {Object.entries(result.whois).map(([key, value]) => (
              <p key={key}><strong>{key}:</strong> {value}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default VerificationResults;
