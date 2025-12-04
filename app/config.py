"""
Configuration management for Asset Monitor
Loads settings from environment variables
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Database
    database_url: str = "sqlite:///./assetmon.db"

    # API Keys
    shodan_api_key: Optional[str] = None

    # Notification
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # Scan Configuration
    scan_threads: int = 50
    dns_rate_limit: int = 100
    http_timeout: int = 10
    http_threads: int = 50

    # Tool Paths
    subfinder_path: str = "subfinder"
    assetfinder_path: str = "assetfinder"
    dnsx_path: str = "dnsx"
    httpx_path: str = "/home/daud/go/bin/httpx"  # Use absolute path to avoid conflict with Python httpx CLI
    gau_path: str = "gau"
    katana_path: str = "katana"
    waybackurls_path: str = "waybackurls"
    amass_path: str = "amass"

    # Subdomain Takeover Detection
    takeover_patterns_cname: str = "vercel.app,netlify.app,github.io,herokuapp.com,s3.amazonaws.com,azurewebsites.net,cloudfront.net"
    takeover_fingerprints: str = "There isn't a GitHub Pages site here,No such app,The specified bucket does not exist,404: Not Found"

    # Timeouts
    tool_timeout: int = 300
    scan_timeout: int = 3600

    # Logging
    log_level: str = "INFO"
    log_file: str = "assetmon.log"

    @property
    def takeover_cname_list(self) -> List[str]:
        """Parse CNAME patterns into list"""
        return [p.strip() for p in self.takeover_patterns_cname.split(",")]

    @property
    def takeover_fingerprint_list(self) -> List[str]:
        """Parse fingerprints into list"""
        return [f.strip() for f in self.takeover_fingerprints.split(",")]

    def validate_tools(self) -> dict:
        """
        Validate that required tools are available
        Returns dict with tool name and availability status
        """
        import shutil

        tools = {
            "subfinder": self.subfinder_path,
            "assetfinder": self.assetfinder_path,
            "dnsx": self.dnsx_path,
            "httpx": self.httpx_path,
            "gau": self.gau_path,
            "katana": self.katana_path,
            "waybackurls": self.waybackurls_path,
        }

        results = {}
        for name, path in tools.items():
            results[name] = shutil.which(path) is not None

        return results


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get settings instance (for dependency injection in FastAPI)"""
    return settings
