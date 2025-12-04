import axios from "axios";
import { VerificationResult, URLVerificationRequest } from "../types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export class PhishGuardAPI {
    /**
     * Verify a URL against multiple security services
     * @param url - The URL to verify
     * @returns Verification results
     */
    static async verifyURL(url: string): Promise<VerificationResult> {
        const payload: URLVerificationRequest = { url };
        const response = await axios.post<VerificationResult>(
            `${API_URL}/verify-url`,
            payload
        );
        return response.data;
    }

    /**
     * Health check for the API
     * @returns Health status
     */
    static async healthCheck(): Promise<{ status: string }> {
        const response = await axios.get(`${API_URL}/health`);
        return response.data;
    }
}
