"""
Celery Tasks for AssetMon
Background tasks for running scans
"""

import logging
from app.celery_app import celery_app
from app.db import SessionLocal
from app.services.orchestrator import ScanOrchestrator
from app.services.notifiers.discord import DiscordNotifier
from app.services.notifiers.base import NotificationManager

logger = logging.getLogger(__name__)


def create_notification_manager(db, project_id):
    """Create notification manager for the project"""
    from app.models import Project
    from app.services.notifiers.slack import SlackNotifier
    from app.services.notifiers.telegram import TelegramNotifier
    import json
    
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return NotificationManager()
    
    manager = NotificationManager()
    
    # Parse notification_config - might be string or dict
    notif_config = project.notification_config
    if isinstance(notif_config, str):
        try:
            notif_config = json.loads(notif_config)
        except (json.JSONDecodeError, TypeError):
            notif_config = {}
    elif notif_config is None:
        notif_config = {}
    
    # Add Discord notifier if configured
    discord_config = notif_config.get("discord")
    if isinstance(discord_config, dict) and discord_config.get("enabled", False):
        webhook_url = discord_config.get("webhook_url")
        if webhook_url:
            manager.add_notifier(DiscordNotifier(webhook_url))
    
    # Add Slack notifier if configured  
    slack_config = notif_config.get("slack")
    if isinstance(slack_config, dict) and slack_config.get("enabled", False):
        manager.add_notifier(SlackNotifier(slack_config))
    
    # Add Telegram notifier if configured
    telegram_config = notif_config.get("telegram")
    if isinstance(telegram_config, dict) and telegram_config.get("enabled", False):
        manager.add_notifier(TelegramNotifier(telegram_config))
    
    return manager


@celery_app.task(bind=True, name="run_scan")
def run_scan_task(self, project_id: int, mode: str = "normal", modules: list = None):
    """
    Celery task to run a scan in background worker
    
    Args:
        project_id: Project ID to scan
        mode: Scan mode (normal/weekly/custom)
        modules: List of modules to run
    """
    logger.info(f"[Celery] Starting scan for project {project_id}, mode={mode}")
    
    # Update task state
    self.update_state(state="RUNNING", meta={"project_id": project_id, "mode": mode})
    
    db = SessionLocal()
    try:
        notification_manager = create_notification_manager(db, project_id)
        orchestrator = ScanOrchestrator(db, notification_manager)
        
        result = orchestrator.run_scan(project_id, mode=mode, modules=modules)
        
        logger.info(f"[Celery] Scan completed for project {project_id}: {result.get('events_generated', 0)} events")
        
        return {
            "status": "completed",
            "project_id": project_id,
            "events_generated": result.get("events_generated", 0),
            "scan_log_id": result.get("scan_log_id")
        }
        
    except Exception as e:
        logger.error(f"[Celery] Scan failed for project {project_id}: {e}")
        return {
            "status": "failed",
            "project_id": project_id,
            "error": str(e)
        }
    finally:
        db.close()


@celery_app.task(name="health_check")
def health_check():
    """Simple health check task"""
    return {"status": "ok", "worker": "running"}
