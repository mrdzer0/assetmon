import sys
import os
sys.path.append(os.getcwd())

from app.services.scanner.favicon_monitor import FaviconMonitor

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/calc_favicon_hash.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"Fetching favicon for {url}...")
    
    # Mock domains/ips for init
    monitor = FaviconMonitor([], [])
    hash_val, favicon_url = monitor.get_favicon_hash(url)
    
    if hash_val:
        print(f"SUCCESS: {url}")
        print(f"Favicon URL: {favicon_url}")
        print(f"Hash: {hash_val}")
    else:
        print(f"FAILED: Could not calculate hash for {url}")

if __name__ == "__main__":
    main()
