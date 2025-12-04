"""
PhishGuard API - Main application entry point
"""
import os
import sys
# import logging # Removed unused import
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.logger import setup_logger

sys.path.append(os.path.dirname(__file__))

# Configure logging
logger = setup_logger(__name__)

app = FastAPI(
    title="PhishGuard API",
    description="URL verification and threat intelligence API",
    version="1.0.0"
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
