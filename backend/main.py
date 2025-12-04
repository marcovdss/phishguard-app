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

# Configure logging
logger = setup_logger(__name__)

# Rate Limiting
from app.core.limiter import limiter

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
app.add_middleware(SlowAPIMiddleware)

# Security Headers Middleware
@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    await secure_headers.set_headers_async(response)
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
