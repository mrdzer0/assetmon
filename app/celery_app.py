"""
Celery Application Configuration
Handles background task processing for scans
"""

from celery import Celery
import os

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "assetmon",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    
    # Task settings
    task_track_started=True,
    task_time_limit=14400,  # 4 hours max per task
    task_soft_time_limit=13800,  # soft limit 3h 50min
    
    # Worker settings
    worker_prefetch_multiplier=1,  # Process one task at a time
    worker_concurrency=2,  # 2 concurrent workers
    
    # Result settings
    result_expires=172800,  # Results expire after 48 hours
)
