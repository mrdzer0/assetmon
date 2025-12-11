# Background Task Queue (Celery + Redis)

AssetMon uses Celery with Redis for background task processing, ensuring the web server remains responsive during long-running scans.

## Architecture

```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  FastAPI     │ --> │   Redis     │ --> │  Celery      │
│  Web Server  │     │  (Broker)   │     │  Worker      │
└──────────────┘     └─────────────┘     └──────────────┘
       ↓                                        ↓
  Handles HTTP                            Runs Scans
  (stays responsive)                  (separate process)
```

## Requirements

- **Redis** - Message broker for task queue
- **Celery** - Python distributed task queue
- **jsbeautifier** - JS beautification for secret scanning

## Installation

### Option 1: Automatic (Recommended)
```bash
./setup_tools.sh
```

### Option 2: Manual
```bash
# Install Redis
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Install Python packages
pip install celery[redis] jsbeautifier
```

## Usage

### Starting the Application

```bash
# Start both Celery worker and web server
./start.sh
```

This single command:
1. Checks/initializes database
2. Starts Celery worker in background (if Redis available)
3. Starts web server on http://0.0.0.0:8000
4. Handles graceful shutdown of all services with Ctrl+C

### Starting Services Separately (Optional)

```bash
# Terminal 1: Start Celery worker only
./start_worker.sh

# Terminal 2: Start web server only
./start_web.sh
```

## Configuration

Environment variables (in `.env`):

```env
# Redis URL (default: localhost:6379)
REDIS_URL=redis://localhost:6379/0
```

## Files

| File | Description |
|------|-------------|
| `app/celery_app.py` | Celery application configuration |
| `app/tasks.py` | Background task definitions |
| `start_worker.sh` | Worker startup script |

## Fallback Behavior

If Celery/Redis is unavailable, AssetMon automatically falls back to FastAPI's built-in `BackgroundTasks`. This works but may cause the web server to become unresponsive during long scans.

## Troubleshooting

### Redis not running
```bash
sudo systemctl start redis
sudo systemctl status redis
```

### Worker not processing tasks
```bash
# Check worker logs
./start_worker.sh

# In another terminal, test task
python3 -c "from app.tasks import health_check; print(health_check.delay().get())"
```

### Permission errors
```bash
# Ensure Redis is accessible
redis-cli ping

# Check Redis logs
sudo journalctl -u redis
```
