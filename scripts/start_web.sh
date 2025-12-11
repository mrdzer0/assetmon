#!/bin/bash

# Asset Monitor - Web Server Startup Script

echo "🚀 Starting Asset Monitor Web Platform..."
echo ""

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

# Start web server
echo "🌐 Starting web server on http://0.0.0.0:8000"
echo "   Press Ctrl+C to stop"
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
