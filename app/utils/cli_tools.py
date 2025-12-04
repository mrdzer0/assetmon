"""
Wrapper functions for external CLI tools
Handles subprocess execution with proper error handling and timeouts
"""

import subprocess
import tempfile
import os
import json
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Raised when a tool execution fails"""
    pass


class ToolNotFoundError(Exception):
    """Raised when a required tool is not found"""
    pass


def check_tool_exists(tool_path: str) -> bool:
    """
    Check if a tool exists in PATH or at specified path
    """
    import shutil
    import os

    # If absolute path, check if file exists directly
    if os.path.isabs(tool_path):
        return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)

    # Otherwise check in PATH
    return shutil.which(tool_path) is not None


def run_command(
    cmd: List[str],
    timeout: Optional[int] = None,
    input_data: Optional[str] = None,
    check: bool = True
) -> subprocess.CompletedProcess:
    """
    Run a command with proper error handling

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds (default from settings)
        input_data: Optional stdin input
        check: Raise exception on non-zero exit code

    Returns:
        CompletedProcess object

    Raises:
        ToolNotFoundError: If command not found
        ToolExecutionError: If execution fails
        subprocess.TimeoutExpired: If timeout exceeded
    """
    if timeout is None:
        timeout = settings.tool_timeout

    if not check_tool_exists(cmd[0]):
        raise ToolNotFoundError(f"Tool not found: {cmd[0]}")

    try:
        logger.info(f"Executing: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            check=False  # We'll handle errors manually
        )

        if check and result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            raise ToolExecutionError(
                f"Command failed with exit code {result.returncode}: {' '.join(cmd)}\nError: {error_msg}"
            )

        return result

    except FileNotFoundError:
        raise ToolNotFoundError(f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timeout after {timeout}s: {' '.join(cmd)}")
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {' '.join(cmd)}, Error: {str(e)}")
        raise ToolExecutionError(f"Execution failed: {str(e)}")


# Subdomain Discovery Tools

def run_subfinder(domains: List[str], use_sources: Optional[List[str]] = None) -> List[str]:
    """
    Run subfinder for subdomain discovery

    Args:
        domains: List of domains to scan
        use_sources: Optional list of sources to use

    Returns:
        List of discovered subdomains
    """
    cmd = [settings.subfinder_path, "-silent"]

    if use_sources:
        cmd.extend(["-sources", ",".join(use_sources)])

    # Use stdin for domains
    domains_input = "\n".join(domains)

    try:
        result = run_command(cmd, input_data=domains_input)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"Subfinder found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        logger.error(f"Subfinder execution failed: {e}")
        return []


def run_assetfinder(domain: str) -> List[str]:
    """
    Run assetfinder for subdomain discovery

    Args:
        domain: Single domain to scan

    Returns:
        List of discovered subdomains
    """
    cmd = [settings.assetfinder_path, "--subs-only", domain]

    try:
        result = run_command(cmd)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"Assetfinder found {len(subdomains)} subdomains for {domain}")
        return subdomains
    except Exception as e:
        logger.error(f"Assetfinder execution failed: {e}")
        return []


# DNS Tools

def run_dnsx(
    hosts: List[str],
    resolve_a: bool = True,
    resolve_cname: bool = True,
    rate_limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Run dnsx for DNS resolution

    Args:
        hosts: List of hostnames to resolve
        resolve_a: Resolve A records
        resolve_cname: Resolve CNAME records
        rate_limit: Rate limit (requests per second)

    Returns:
        List of DNS records as dicts
    """
    if not hosts:
        return []

    cmd = [settings.dnsx_path, "-silent", "-json"]

    if resolve_a:
        cmd.append("-a")
    if resolve_cname:
        cmd.append("-cname")
    if rate_limit:
        cmd.extend(["-rate-limit", str(rate_limit)])
    elif settings.dns_rate_limit:
        cmd.extend(["-rate-limit", str(settings.dns_rate_limit)])

    # Write hosts to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("\n".join(hosts))
        hosts_file = f.name

    try:
        cmd.extend(["-list", hosts_file])
        result = run_command(cmd)

        # Parse JSON output
        records = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse dnsx JSON: {line}")

        logger.info(f"dnsx resolved {len(records)} hosts")
        return records

    except Exception as e:
        logger.error(f"dnsx execution failed: {e}")
        return []
    finally:
        # Cleanup temp file
        try:
            os.unlink(hosts_file)
        except:
            pass


# HTTP Tools

def run_httpx(
    urls: List[str],
    threads: Optional[int] = None,
    timeout: Optional[int] = None,
    tech_detect: bool = True,
    status_code: bool = True,
    title: bool = True,
    content_length: bool = True,
    screenshot: bool = False
) -> List[Dict[str, Any]]:
    """
    Run httpx for HTTP probing

    Args:
        urls: List of URLs/hosts to probe
        threads: Number of threads
        timeout: Timeout per request
        tech_detect: Enable technology detection
        status_code: Include status code
        title: Include page title
        content_length: Include content length
        screenshot: Capture screenshots (requires headless browser)

    Returns:
        List of HTTP records as dicts
    """
    if not urls:
        return []

    cmd = [settings.httpx_path, "-silent", "-json"]

    if threads:
        cmd.extend(["-threads", str(threads)])
    elif settings.http_threads:
        cmd.extend(["-threads", str(settings.http_threads)])

    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    elif settings.http_timeout:
        cmd.extend(["-timeout", str(settings.http_timeout)])

    if tech_detect:
        cmd.append("-tech-detect")
    if status_code:
        cmd.append("-status-code")
    if title:
        cmd.append("-title")
    if content_length:
        cmd.append("-content-length")
    if screenshot:
        cmd.extend(["-screenshot", "-system-chrome"])

    # Also get IP, CNAME, CDN info
    cmd.extend(["-ip", "-cname", "-cdn"])

    # Write URLs to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("\n".join(urls))
        urls_file = f.name

    try:
        cmd.extend(["-list", urls_file])
        # httpx can return exit code 1 even on partial success, so don't check exit code
        result = run_command(cmd, timeout=settings.scan_timeout, check=False)

        # Parse JSON output
        records = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse httpx JSON: {line}")

        logger.info(f"httpx probed {len(records)} URLs")
        return records

    except Exception as e:
        logger.error(f"httpx execution failed: {e}")
        return []
    finally:
        # Cleanup temp file
        try:
            os.unlink(urls_file)
        except:
            pass


# Endpoint Discovery Tools

def run_waybackurls(domain: str) -> List[str]:
    """
    Run waybackurls for historical URL discovery

    Args:
        domain: Domain to fetch URLs for

    Returns:
        List of URLs
    """
    cmd = [settings.waybackurls_path, domain]

    try:
        result = run_command(cmd, timeout=settings.scan_timeout)
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"waybackurls found {len(urls)} URLs for {domain}")
        return urls
    except Exception as e:
        logger.error(f"waybackurls execution failed: {e}")
        return []


def run_gau(domain: str, threads: int = 5) -> List[str]:
    """
    Run gau (GetAllUrls) for URL discovery

    Args:
        domain: Domain to fetch URLs for
        threads: Number of threads

    Returns:
        List of URLs
    """
    cmd = [settings.gau_path, "--threads", str(threads), domain]

    try:
        result = run_command(cmd, timeout=settings.scan_timeout)
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"gau found {len(urls)} URLs for {domain}")
        return urls
    except Exception as e:
        logger.error(f"gau execution failed: {e}")
        return []


def run_katana(
    urls: List[str],
    depth: int = 2,
    js_crawl: bool = True,
    timeout: Optional[int] = None
) -> List[str]:
    """
    Run katana for web crawling

    Args:
        urls: List of URLs to crawl
        depth: Crawl depth
        js_crawl: Enable JavaScript parsing
        timeout: Overall timeout

    Returns:
        List of discovered URLs
    """
    if not urls:
        return []

    cmd = [
        settings.katana_path,
        "-silent",
        "-depth", str(depth),
        "-concurrency", "10"
    ]

    if js_crawl:
        cmd.append("-js-crawl")

    # Write URLs to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("\n".join(urls))
        urls_file = f.name

    try:
        cmd.extend(["-list", urls_file])
        result = run_command(cmd, timeout=timeout or settings.scan_timeout)
        discovered_urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"katana discovered {len(discovered_urls)} URLs")
        return discovered_urls

    except Exception as e:
        logger.error(f"katana execution failed: {e}")
        return []
    finally:
        # Cleanup temp file
        try:
            os.unlink(urls_file)
        except:
            pass


# Shodan Integration (using Python API, not CLI)

def query_shodan(query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Query Shodan API

    Args:
        query: Shodan search query
        limit: Maximum results

    Returns:
        List of Shodan results
    """
    if not settings.shodan_api_key:
        logger.warning("Shodan API key not configured")
        return []

    try:
        import shodan

        api = shodan.Shodan(settings.shodan_api_key)
        results = api.search(query, limit=limit)

        logger.info(f"Shodan found {len(results['matches'])} results for query: {query}")
        return results['matches']

    except ImportError:
        logger.error("shodan Python package not installed")
        return []
    except Exception as e:
        logger.error(f"Shodan query failed: {e}")
        return []


def shodan_host_info(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get Shodan information for a specific IP

    Args:
        ip: IP address

    Returns:
        Host information dict or None
    """
    if not settings.shodan_api_key:
        logger.warning("Shodan API key not configured")
        return None

    try:
        import shodan

        api = shodan.Shodan(settings.shodan_api_key)
        host = api.host(ip)

        logger.info(f"Retrieved Shodan info for {ip}")
        return host

    except ImportError:
        logger.error("shodan Python package not installed")
        return None
    except Exception as e:
        logger.error(f"Shodan host lookup failed for {ip}: {e}")
        return None
