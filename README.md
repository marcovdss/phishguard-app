# PhishGuard App

PhishGuard is a professional, full-stack URL verification tool designed to protect users from phishing and malicious websites. It features a modern, premium UI with real-time threat intelligence powered by multiple security services.

## ✨ Features

- **🎨 Premium Dark UI**: Modern glassmorphism design with smooth animations
- **🔍 Multi-Source Verification**: 
  - Google Safe Browsing API
  - VirusTotal Analysis
  - PhishTank Database
  - SSL Certificate Validation
  - TLD (Top-Level Domain) Verification
  - WHOIS Registration Data
- **⚡ Real-time Analysis**: Instant feedback with visual status indicators
- **🛡️ Robust Error Handling**: Graceful failure handling for all external services
- **🔒 Enhanced Security**:
  - Rate Limiting (10 requests/minute)
  - HTTP Security Headers (HSTS, CSP, X-Frame-Options)
- **📱 Responsive Design**: Works seamlessly on desktop and mobile devices

## Project Structure

```
phishguard-app/
├── backend/           # FastAPI application
│   ├── app/           # Application source code
│   │   ├── api/       # API routes
│   │   ├── core/      # Config and logging
│   │   ├── models/    # Pydantic models
│   │   └── services/  # Business logic
│   ├── main.py        # Entry point
│   └── requirements.txt
├── frontend/          # Next.js application
│   ├── app/           # App router pages & components
│   └── public/        # Static assets
└── package.json       # Root scripts
```

## Prerequisites

- **Node.js** (v16 or higher)
- **Python** (v3.8 or higher)
- **API Keys** (optional, for full functionality):
  - Google Safe Browsing API Key
  - VirusTotal API Key

## Setup and Installation

### 1. Install Dependencies

Run the following command in the root directory to install both backend and frontend dependencies:

```bash
npm install
```

*This automatically runs `pip install -r requirements.txt` for the backend and `npm install` for the frontend.*

### 2. Configure API Keys (Optional)

Create a `.env` file in the `backend` directory with your API keys:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

**Note**: The application will work without API keys, but Google Safe Browsing and VirusTotal checks will return "Error" status.

## Running the Application

### Development Mode

To run both the backend and frontend concurrently:

```bash
npm run dev
```

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### Running Separately

**Backend only:**
```bash
cd backend
python -m uvicorn main:app --reload
```

**Frontend only:**
```bash
cd frontend
npm run dev
```

## Testing

To run the backend tests:

```bash
cd backend
pytest
```

## Usage

1. Open http://localhost:3000 in your browser
2. Enter a URL to verify (e.g., `google.com` or `example.com`)
3. Click "Verify" or press Enter
4. View comprehensive security analysis in the results cards

## Technology Stack

### Frontend
- **Next.js 13+** - React framework with App Router
- **TypeScript** - Type-safe development
- **Axios** - HTTP client
- **Custom CSS** - Premium glassmorphism design system

### Backend
- **FastAPI** - Modern Python web framework
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation
- **SlowAPI** - Rate limiting
- **Secure** - HTTP security headers
- **python-whois** - Domain registration lookup
- **BeautifulSoup4** - HTML parsing
- **Requests** - HTTP library

## API Endpoints

### `POST /verify-url`
Verify a URL against multiple security services.

**Request Body:**
```json
{
  "url": "example.com"
}
```

**Response:**
```json
{
  "google_safe_browsing": "Safe",
  "virustotal": "Safe",
  "phishtank": "Safe",
  "ssl": "Valid",
  "ssl_days_remaining": 365,
  "tld": "Valid",
  "whois": {
    "Domain Name": "EXAMPLE.COM",
    "Registrar": "Example Registrar",
    "Creation Date": "1995-08-14 04:00:00",
    "Expiration Date": "2025-08-13 04:00:00",
    "Name Servers": "ns1.example.com, ns2.example.com"
  }
}
```

### `GET /verify-url?url=example.com`
Alternative GET endpoint for convenience.

## Troubleshooting

### Backend fails to start
- Ensure Python is installed and in your PATH
- Try running `pip install -r backend/requirements.txt` manually
- Check if port 8000 is already in use

### Frontend fails to start
- Ensure Node.js is installed
- Try running `npm install` in `frontend`
- Check if port 3000 is already in use

### API checks return "Error"
- Verify your API keys are correctly set in `backend/.env`
- Check your internet connection
- Review backend console logs for specific error messages

## Future Enhancements

- [ ] User authentication and saved scan history
- [ ] Batch URL scanning
- [ ] Export reports (PDF/CSV)
- [ ] Browser extension
- [ ] Email notification alerts
- [ ] Custom blacklist management

## License

This project is provided as-is for educational and security research purposes.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.