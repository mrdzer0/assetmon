#!/bin/bash

# Asset Monitor - Combined Startup Script
# Starts both Celery worker and web server

set -e

echo "==========================================="
echo "🚀 Asset Monitor - Starting Services"
echo "==========================================="
echo ""

# Change to script directory
cd "$(dirname "$0")"

# Check if database exists
if [ ! -f "assetmon.db" ]; then
    echo "📊 Initializing database..."
    python3 -c "from app.db import init_db; init_db()"
    echo "✓ Database initialized"
    echo ""
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found"
    echo "   Copying from .env.example..."
    cp .env.example .env
    echo "   Please edit .env and add your API keys"
    echo ""
fi

# Check Redis
REDIS_AVAILABLE=false
if command -v redis-cli &> /dev/null && redis-cli ping &> /dev/null; then
    echo "✅ Redis: running"
    REDIS_AVAILABLE=true
else
    echo "⚠️  Redis not available - using BackgroundTasks fallback"
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    
    # Kill Celery worker if running
    if [ ! -z "$CELERY_PID" ]; then
        echo "   Stopping Celery worker (PID: $CELERY_PID)..."
        kill $CELERY_PID 2>/dev/null || true
    fi
    
    echo "✓ All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start Celery worker in background (if Redis available)
if [ "$REDIS_AVAILABLE" = true ]; then
    echo ""
    echo "🔧 Starting Celery worker in background..."
    celery -A app.celery_app worker --loglevel=warning --concurrency=2 &
    CELERY_PID=$!
    sleep 2
    
    if ps -p $CELERY_PID > /dev/null 2>&1; then
        echo "✅ Celery worker started (PID: $CELERY_PID)"
    else
        echo "⚠️  Celery worker failed to start - using BackgroundTasks fallback"
        CELERY_PID=""
    fi
fi

# Start web server
echo ""
echo "==========================================="
echo "🌐 Starting web server on http://0.0.0.0:8000"
echo "   Press Ctrl+C to stop all services"
echo "==========================================="
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
