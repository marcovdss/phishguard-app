// Type definitions for PhishGuard frontend

export interface VerificationResult {
    google_safe_browsing: string;
    virustotal: string;
    ssl: string;
    ssl_days_remaining: number | null;
    tld: string;
    whois?: Record<string, string>;
}

export interface URLVerificationRequest {
    url: string;
}

export type StatusType = "Safe" | "Malicious" | "Warning" | "Error" | "Valid" | "Invalid";
