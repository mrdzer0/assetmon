"""
Background job management with APScheduler
"""

import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Project
from app.services.orchestrator import ScanOrchestrator
from app.services.notifiers.base import NotificationManager
from app.services.notifiers.slack import SlackNotifier
from app.services.notifiers.discord import DiscordNotifier
from app.services.notifiers.telegram import TelegramNotifier

logger = logging.getLogger(__name__)


class JobManager:
    """Manages background jobs for scheduled scanning"""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        logger.info("Job scheduler started")

    def add_scan_job(
        self,
        project_id: int,
        cron_expression: str,
        scan_mode: str = "normal",
        job_id: str = None
    ):
        """
        Add a scheduled scan job

        Args:
            project_id: Project ID to scan
            cron_expression: Cron expression (e.g., "0 0 * * *" for daily at midnight)
            scan_mode: Scan mode ("normal" or "weekly")
            job_id: Optional custom job ID
        """
        if not job_id:
            job_id = f"scan_project_{project_id}_{scan_mode}"

        # Remove existing job if any
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        # Parse cron expression
        parts = cron_expression.split()
        if len(parts) != 5:
            raise ValueError("Invalid cron expression. Format: minute hour day month day_of_week")

        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4]
        )

        # Add job
        self.scheduler.add_job(
            func=self._execute_scan,
            trigger=trigger,
            args=[project_id, scan_mode],
            id=job_id,
            name=f"Scan project {project_id} ({scan_mode})",
            replace_existing=True
        )

        logger.info(f"Added scheduled scan job: {job_id} with cron '{cron_expression}'")

    def remove_scan_job(self, job_id: str):
        """Remove a scheduled scan job"""
        try:
            self.scheduler.remove_job(job_id)
            logger.info(f"Removed scan job: {job_id}")
        except Exception as e:
            logger.error(f"Failed to remove job {job_id}: {e}")

    def get_scheduled_jobs(self):
        """Get all scheduled jobs"""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time,
                "trigger": str(job.trigger)
            })
        return jobs

    def _execute_scan(self, project_id: int, scan_mode: str):
        """Execute a scan (called by scheduler)"""
        logger.info(f"Executing scheduled scan: project={project_id}, mode={scan_mode}")

        db = SessionLocal()
        try:
            # Create notification manager
            notification_manager = self._create_notification_manager(db, project_id)

            # Create orchestrator and run scan
            orchestrator = ScanOrchestrator(db, notification_manager)
            result = orchestrator.run_scan(project_id, mode=scan_mode)

            logger.info(f"Scheduled scan completed: {result['events_generated']} events")

        except Exception as e:
            logger.error(f"Scheduled scan failed: {e}", exc_info=True)

        finally:
            db.close()

    def _create_notification_manager(self, db: Session, project_id: int) -> NotificationManager:
        """Create notification manager with configured channels"""
        manager = NotificationManager()

        # Get project
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return manager

        # Get notification config
        notif_config = project.notification_config or {}

        # Add Slack notifier
        if notif_config.get("slack", {}).get("enabled", False):
            slack_config = notif_config.get("slack", {})
            manager.add_notifier(SlackNotifier(slack_config))

        # Add Discord notifier
        if notif_config.get("discord", {}).get("enabled", False):
            discord_config = notif_config.get("discord", {})
            manager.add_notifier(DiscordNotifier(discord_config))

        # Add Telegram notifier
        if notif_config.get("telegram", {}).get("enabled", False):
            telegram_config = notif_config.get("telegram", {})
            manager.add_notifier(TelegramNotifier(telegram_config))

        return manager

    def shutdown(self):
        """Shutdown the scheduler"""
        self.scheduler.shutdown()
        logger.info("Job scheduler shutdown")


# Global job manager instance
job_manager = None


def get_job_manager() -> JobManager:
    """Get or create job manager instance"""
    global job_manager
    if job_manager is None:
        job_manager = JobManager()
    return job_manager


def setup_default_jobs(db: Session):
    """
    Setup default scheduled jobs for all active projects
    This should be called on application startup
    """
    logger.info("Setting up default scheduled jobs...")

    manager = get_job_manager()

    # Get all active projects
    projects = db.query(Project).filter(Project.is_active == True).all()

    for project in projects:
        try:
            # Get schedule config from project
            config = project.config or {}
            schedule = config.get("schedule", {})

            # Normal scan schedule (default: daily at 2 AM)
            normal_cron = schedule.get("normal", "0 2 * * *")
            if schedule.get("normal_enabled", True):
                manager.add_scan_job(
                    project.id,
                    normal_cron,
                    scan_mode="normal",
                    job_id=f"scan_project_{project.id}_normal"
                )

            # Weekly scan schedule (default: Sunday at 3 AM)
            weekly_cron = schedule.get("weekly", "0 3 * * 0")
            if schedule.get("weekly_enabled", False):
                manager.add_scan_job(
                    project.id,
                    weekly_cron,
                    scan_mode="weekly",
                    job_id=f"scan_project_{project.id}_weekly"
                )

        except Exception as e:
            logger.error(f"Failed to setup jobs for project {project.id}: {e}")

    logger.info(f"Setup complete. Active jobs: {len(manager.get_scheduled_jobs())}")
