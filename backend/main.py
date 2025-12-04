import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.api.routes import router
from app.core.logger import setup_logger

sys.path.append(os.path.dirname(__file__))

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from secure import Secure
from app.core.logger import setup_logger

# Configure logging
logger = setup_logger(__name__)

# Rate Limiting
limiter = Limiter(key_func=get_remote_address)

# Security Headers
secure_headers = Secure.with_default_headers()

app = FastAPI(
    title="PhishGuard API",
    description="URL verification and threat intelligence API",
    version="1.0.0"
)

# Add SlowAPI middleware
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)
# app.add_middleware(SlowAPIMiddleware)

import time
request_counts = {}

@app.middleware("http")
async def simple_rate_limit(request, call_next):
    # Simple rate limiting for verify-url
    if request.url.path == "/verify-url" and request.method == "POST":
        ip = get_remote_address(request)
        now = time.time()
        # Clean up old keys (optional, but good for memory)
        # For simplicity, just use minute bucket
        key = f"{ip}:{int(now // 60)}"
        
        current = request_counts.get(key, 0)
        if current >= 10:
            return JSONResponse(status_code=429, content={"message": "Rate limit exceeded"})
        
        request_counts[key] = current + 1
        
    response = await call_next(request)
    return response

async def debug_middleware(request, call_next):
    with open("debug_trace.txt", "a") as f:
        f.write("Debug middleware: Request received\n")
    try:
        response = await call_next(request)
        with open("debug_trace.txt", "a") as f:
            f.write("Debug middleware: Response generated\n")
        return response
    except Exception as e:
        with open("debug_trace.txt", "a") as f:
            f.write(f"Debug middleware caught exception: {e}\n")
            import traceback
            traceback.print_exc(file=f)
        raise e

# Security Headers Middleware
@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    # secure_headers.framework.fastapi(response) # This API seems to be missing
    # Try generic set method or manual headers
    # secure_headers.set(response)
    # Actually, let's just use the headers dict
    for header, value in secure_headers.headers.items():
        response.headers[header] = value
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error"},
    )

# CORS Middleware - Allow all origins for development
# TODO: Restrict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, tags=["verification"])

# Add debug middleware last so it runs first
app.add_middleware(BaseHTTPMiddleware, dispatch=debug_middleware)


@app.on_event("startup")
async def startup_event():
    """Log application startup"""
    logger.info("PhishGuard API starting up...")


@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "message": "PhishGuard API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
