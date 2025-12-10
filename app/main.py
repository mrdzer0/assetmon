"""
Main FastAPI application
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.db import init_db, SessionLocal
from app.config import settings
from app.jobs import setup_default_jobs, get_job_manager
from app.routers import projects, scans, events, dashboard, auth, reports, settings as settings_router

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(settings.log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    """
    # Startup
    logger.info("Starting Asset Monitor application...")

    # Initialize database
    logger.info("Initializing database...")
    init_db()

    # Setup scheduled jobs
    logger.info("Setting up scheduled jobs...")
    db = SessionLocal()
    try:
        setup_default_jobs(db)
    finally:
        db.close()

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down Asset Monitor application...")

    # Shutdown job scheduler
    job_manager = get_job_manager()
    job_manager.shutdown()

    logger.info("Application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Asset Monitor",
    description="Attack Surface Monitoring Platform",
    version="0.1.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handler for authentication errors
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions - redirect to login for 401 on HTML pages"""
    if exc.status_code == 401:
        # Check if this is a browser request (HTML)
        accept = request.headers.get("accept", "")
        if "text/html" in accept or request.url.path in ["/", "/projects", "/events", "/schedules", "/settings"]:
            # Redirect to login page
            return RedirectResponse(url="/login", status_code=302)

    # For API requests or other status codes, return JSON
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

# Mount static files
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# Include routers
app.include_router(auth.router)  # Auth routes (login/logout) - no auth required
app.include_router(dashboard.router)  # UI routes (no prefix) - auth required
app.include_router(projects.router)  # API routes - auth required
app.include_router(scans.router)  # API routes - auth required
app.include_router(events.router)  # API routes - auth required
app.include_router(reports.router)  # Reports API - auth required
app.include_router(settings_router.router)  # Settings API - auth required


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "database": "connected"
    }


@app.get("/api/status")
def get_status():
    """Get application status"""
    from app.config import settings

    # Check tools
    tools_status = settings.validate_tools()

    # Get scheduler status
    job_manager = get_job_manager()
    scheduled_jobs = job_manager.get_scheduled_jobs()

    return {
        "status": "running",
        "version": "0.1.0",
        "tools": tools_status,
        "scheduled_jobs": len(scheduled_jobs),
        "shodan_configured": bool(settings.shodan_api_key)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
