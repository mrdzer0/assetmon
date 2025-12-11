#!/bin/bash
# Start Celery worker for AssetMon background processing

echo "🚀 Starting Celery Worker..."
echo "   Press Ctrl+C to stop"
echo ""

# Check if Redis is running
if ! redis-cli ping > /dev/null 2>&1; then
    echo "❌ Redis is not running. Please start Redis first:"
    echo "   sudo systemctl start redis"
    exit 1
fi

echo "✅ Redis connection OK"
echo ""

# Start Celery worker
cd "$(dirname "$0")"
celery -A app.celery_app worker --loglevel=info --concurrency=2
