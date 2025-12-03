#!/usr/bin/env python3
"""
Asset Monitor CLI
Simple command-line interface for testing scan functionality
"""

import click
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List

from app.config import settings
from app.services.scanner.subdomains import discover_subdomains
from app.services.scanner.dns_monitor import monitor_dns
from app.services.scanner.http_monitor import monitor_http
from app.services.scanner.shodan_monitor import scan_with_shodan
from app.services.scanner.endpoints import discover_endpoints

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def save_results(data: dict, output_file: str):
    """Save results to JSON file"""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

    click.echo(f"\n✓ Results saved to: {output_file}")


@click.group()
@click.version_option(version='0.1.0')
def cli():
    """Asset Monitor - Attack Surface Monitoring Tool"""
    pass


@cli.command()
@click.option('--domains', '-d', required=True, multiple=True, help='Target domain(s)')
@click.option('--sources', '-s', multiple=True,
              type=click.Choice(['subfinder', 'assetfinder', 'crtsh']),
              help='Subdomain sources to use (default: all)')
@click.option('--output', '-o', default='results/subdomains.json', help='Output file')
def subdomains(domains: tuple, sources: tuple, output: str):
    """Discover subdomains for target domain(s)"""
    click.echo(f"\n🔍 Discovering subdomains for: {', '.join(domains)}")

    sources_list = list(sources) if sources else None

    try:
        results = discover_subdomains(list(domains), sources=sources_list)

        click.echo(f"\n✓ Found {results['count']} unique subdomains")
        click.echo(f"\nSources breakdown:")
        for source, data in results.get('sources', {}).items():
            click.echo(f"  - {source}: {data.get('count', 0)} subdomains")

        save_results(results, output)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)
        raise


@cli.command()
@click.option('--subdomains-file', '-f', type=click.Path(exists=True),
              help='File containing subdomains (one per line)')
@click.option('--subdomains', '-s', multiple=True, help='Subdomain(s) to check')
@click.option('--rate-limit', '-r', type=int, help='DNS rate limit')
@click.option('--output', '-o', default='results/dns.json', help='Output file')
def dns(subdomains_file: str, subdomains: tuple, rate_limit: int, output: str):
    """Resolve DNS and detect potential takeovers"""
    # Load subdomains
    subdomain_list = list(subdomains) if subdomains else []

    if subdomains_file:
        with open(subdomains_file, 'r') as f:
            subdomain_list.extend([line.strip() for line in f if line.strip()])

    if not subdomain_list:
        click.echo("✗ No subdomains provided. Use --subdomains or --subdomains-file", err=True)
        return

    click.echo(f"\n🔍 Resolving DNS for {len(subdomain_list)} subdomains")

    try:
        results = monitor_dns(subdomain_list, rate_limit=rate_limit)

        stats = results['stats']
        click.echo(f"\n✓ DNS resolution complete:")
        click.echo(f"  - Resolved: {stats['resolved']}/{stats['total']}")
        click.echo(f"  - Failed: {stats['failed']}")

        takeovers = results.get('takeover_findings', [])
        if takeovers:
            click.echo(f"\n⚠️  Potential subdomain takeovers: {len(takeovers)}")
            for finding in takeovers:
                click.echo(f"  - {finding['subdomain']} -> {finding['cname']} ({finding['service']})")
        else:
            click.echo(f"\n✓ No potential takeovers detected")

        save_results(results, output)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)
        raise


@cli.command()
@click.option('--targets-file', '-f', type=click.Path(exists=True),
              help='File containing targets (one per line)')
@click.option('--targets', '-t', multiple=True, help='Target URL(s) or hostname(s)')
@click.option('--threads', type=int, help='Number of threads')
@click.option('--timeout', type=int, help='Timeout per request')
@click.option('--output', '-o', default='results/http.json', help='Output file')
def http(targets_file: str, targets: tuple, threads: int, timeout: int, output: str):
    """Probe HTTP endpoints"""
    # Load targets
    target_list = list(targets) if targets else []

    if targets_file:
        with open(targets_file, 'r') as f:
            target_list.extend([line.strip() for line in f if line.strip()])

    if not target_list:
        click.echo("✗ No targets provided. Use --targets or --targets-file", err=True)
        return

    click.echo(f"\n🔍 Probing HTTP for {len(target_list)} targets")

    try:
        results = monitor_http(target_list, threads=threads, timeout=timeout)

        stats = results['stats']
        click.echo(f"\n✓ HTTP probing complete:")
        click.echo(f"  - Success: {stats['success']}/{stats['total']}")
        click.echo(f"  - Failed: {stats['failed']}")

        takeovers = results.get('takeover_findings', [])
        if takeovers:
            click.echo(f"\n⚠️  Potential takeovers (HTTP fingerprints): {len(takeovers)}")
            for finding in takeovers:
                click.echo(f"  - {finding['url']}: '{finding['fingerprint']}'")

        save_results(results, output)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)
        raise


@cli.command()
@click.option('--ips', '-i', multiple=True, help='IP address(es) to scan')
@click.option('--domains', '-d', multiple=True, help='Domain(s) to search')
@click.option('--mode', type=click.Choice(['ip', 'domain']), default='ip',
              help='Query mode: ip or domain')
@click.option('--output', '-o', default='results/shodan.json', help='Output file')
def shodan(ips: tuple, domains: tuple, mode: str, output: str):
    """Scan with Shodan for ports and vulnerabilities"""
    if not settings.shodan_api_key:
        click.echo("✗ Shodan API key not configured. Set SHODAN_API_KEY in .env", err=True)
        return

    targets = list(ips if mode == 'ip' else domains)

    if not targets:
        click.echo(f"✗ No targets provided. Use --ips or --domains", err=True)
        return

    click.echo(f"\n🔍 Scanning {len(targets)} targets with Shodan ({mode} mode)")

    try:
        results = scan_with_shodan(targets, query_mode=mode)

        stats = results['stats']
        click.echo(f"\n✓ Shodan scan complete:")
        click.echo(f"  - Hosts found: {stats['found']}/{stats['total']}")
        click.echo(f"  - Vulnerabilities: {stats['vulns']}")

        if results.get('vulnerabilities'):
            click.echo(f"\n⚠️  Vulnerabilities found:")
            for vuln in results['vulnerabilities'][:10]:  # Show first 10
                click.echo(f"  - {vuln['ip']}: {vuln['cve']}")

        save_results(results, output)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)
        raise


@cli.command()
@click.option('--domains', '-d', required=True, multiple=True, help='Target domain(s)')
@click.option('--subdomains-file', '-f', type=click.Path(exists=True),
              help='File with subdomains for crawling (for katana)')
@click.option('--sources', '-s', multiple=True,
              type=click.Choice(['waybackurls', 'gau', 'katana']),
              help='Endpoint sources to use (default: waybackurls, gau)')
@click.option('--depth', type=int, default=2, help='Crawl depth for katana')
@click.option('--output', '-o', default='results/endpoints.json', help='Output file')
def endpoints(domains: tuple, subdomains_file: str, sources: tuple, depth: int, output: str):
    """Discover endpoints and JS files (weekly scan)"""
    click.echo(f"\n🔍 Discovering endpoints for: {', '.join(domains)}")
    click.echo(f"⚠️  This can take a long time...")

    # Load subdomains if provided
    subdomain_list = []
    if subdomains_file:
        with open(subdomains_file, 'r') as f:
            subdomain_list = [line.strip() for line in f if line.strip()]

    sources_list = list(sources) if sources else ['waybackurls', 'gau']

    try:
        results = discover_endpoints(
            list(domains),
            subdomains=subdomain_list,
            sources=sources_list,
            crawl_depth=depth
        )

        stats = results['stats']
        click.echo(f"\n✓ Endpoint discovery complete:")
        click.echo(f"  - Total URLs: {stats['total_urls']}")
        click.echo(f"  - JS files: {stats['total_js_files']}")
        click.echo(f"  - API endpoints: {stats['total_api_endpoints']}")

        click.echo(f"\nSources breakdown:")
        for source, data in results.get('sources', {}).items():
            click.echo(f"  - {source}: {data.get('urls_count', 0)} URLs, {data.get('js_files_count', 0)} JS files")

        save_results(results, output)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)
        raise


@cli.command()
@click.option('--domains', '-d', required=True, multiple=True, help='Target domain(s)')
@click.option('--mode', type=click.Choice(['normal', 'weekly']), default='normal',
              help='Scan mode: normal (faster) or weekly (includes endpoints)')
@click.option('--output-dir', '-o', default='results/full_scan', help='Output directory')
def scan(domains: tuple, mode: str, output_dir: str):
    """Run a full scan (subdomains, DNS, HTTP, Shodan)"""
    click.echo(f"\n🚀 Starting {mode} scan for: {', '.join(domains)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    all_results = {
        "scan_mode": mode,
        "domains": list(domains),
        "timestamp": timestamp,
        "results": {}
    }

    try:
        # 1. Subdomain Discovery
        click.echo("\n[1/4] Discovering subdomains...")
        subdomain_results = discover_subdomains(list(domains))
        all_results["results"]["subdomains"] = subdomain_results
        subdomains = subdomain_results["subdomains"]
        click.echo(f"  ✓ Found {len(subdomains)} subdomains")

        # 2. DNS Resolution
        click.echo("\n[2/4] Resolving DNS...")
        dns_results = monitor_dns(subdomains)
        all_results["results"]["dns"] = dns_results
        click.echo(f"  ✓ Resolved {dns_results['stats']['resolved']} records")

        if dns_results.get('takeover_findings'):
            click.echo(f"  ⚠️  {len(dns_results['takeover_findings'])} potential takeovers detected")

        # 3. HTTP Probing
        click.echo("\n[3/4] Probing HTTP...")
        http_results = monitor_http(subdomains)
        all_results["results"]["http"] = http_results
        click.echo(f"  ✓ Probed {http_results['stats']['success']} endpoints")

        # 4. Shodan Scan (if API key configured)
        click.echo("\n[4/4] Scanning with Shodan...")
        if settings.shodan_api_key:
            # Extract IPs from DNS results
            ips = set()
            for subdomain, record in dns_results['dns_records'].items():
                ips.update(record.get('a', []))

            shodan_results = scan_with_shodan(list(ips), query_mode='ip')
            all_results["results"]["shodan"] = shodan_results
            click.echo(f"  ✓ Scanned {shodan_results['stats']['found']} hosts")
        else:
            click.echo(f"  ⚠️  Skipped (no API key)")

        # 5. Endpoint Discovery (weekly mode only)
        if mode == 'weekly':
            click.echo("\n[WEEKLY] Discovering endpoints...")
            endpoint_results = discover_endpoints(
                list(domains),
                subdomains=subdomains,
                sources=['waybackurls', 'gau']
            )
            all_results["results"]["endpoints"] = endpoint_results
            click.echo(f"  ✓ Found {endpoint_results['stats']['total_urls']} URLs")

        # Save results
        output_file = output_path / f"scan_{timestamp}.json"
        save_results(all_results, str(output_file))

        click.echo(f"\n✅ Scan complete!")

    except Exception as e:
        click.echo(f"\n✗ Scan failed: {e}", err=True)
        raise


@cli.command()
def verify():
    """Verify tool installations"""
    click.echo("\n🔧 Verifying tool installations...\n")

    tools = settings.validate_tools()

    all_good = True
    for tool, available in tools.items():
        status = "✓" if available else "✗"
        click.echo(f"{status} {tool}: {'installed' if available else 'NOT FOUND'}")
        if not available:
            all_good = False

    # Check Shodan API
    click.echo(f"\nShodan API key: {'✓ configured' if settings.shodan_api_key else '✗ not configured'}")

    if all_good:
        click.echo(f"\n✅ All tools are ready!")
    else:
        click.echo(f"\n⚠️  Some tools are missing. Run: ./setup_tools.sh")


if __name__ == '__main__':
    cli()
