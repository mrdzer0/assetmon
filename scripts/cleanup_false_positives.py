#!/usr/bin/env python3
"""
False Positive Cleanup Script
Removes endpoint_new events that were incorrectly flagged as sensitive
due to substring matching bugs (e.g., "bold" matching "old", "star" matching "tar")
"""

import re
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal
from app.models import Event, EventType


# Patterns that indicate false positives
FALSE_POSITIVE_PATTERNS = [
    # Font files
    r'\.woff2?$', r'\.ttf$', r'\.eot$', r'\.otf$',
    # Images
    r'\.png$', r'\.jpe?g$', r'\.gif$', r'\.svg$', r'\.ico$', r'\.webp$',
    # Media
    r'\.mp[34]$', r'\.webm$', r'\.wav$',
    # Stylesheets
    r'\.css$', r'\.less$', r'\.s[ac]ss$',
    # Source maps
    r'\.map$',
    # Minified JS libraries (common ones)
    r'jquery[\.\-]', r'react[\.\-]', r'angular[\.\-]', r'vue[\.\-]',
    r'bootstrap[\.\-]', r'lodash[\.\-]', r'moment[\.\-]', r'axios[\.\-]',
]

# Keywords that were incorrectly matching substrings
SUBSTRING_FALSE_POSITIVES = {
    'old': ['bold', 'cold', 'fold', 'gold', 'hold', 'mold', 'sold', 'told', 'folder'],
    'tar': ['star', 'guitar', 'tartan', 'starter', 'avatar'],
    'zip': ['jszip', 'unzip', 'zipcode'],
    'bak': ['eback', 'callback', 'playback'],
    'dump': ['dumpling'],
    'sql': ['mysql', 'nosql', 'postgresql'],
}


def is_false_positive(url: str, matched_keywords: list) -> bool:
    """
    Check if an event is a false positive based on URL and matched keywords
    """
    url_lower = url.lower()
    
    # Check file extension patterns
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    
    # Check substring false positives
    for keyword, false_matches in SUBSTRING_FALSE_POSITIVES.items():
        if keyword in matched_keywords:
            for false_match in false_matches:
                if false_match in url_lower:
                    return True
    
    return False


def cleanup_false_positives(dry_run: bool = True, project_id: int = None):
    """
    Remove false positive endpoint_new events from database
    
    Args:
        dry_run: If True, only show what would be deleted without actually deleting
        project_id: Optional project ID to limit cleanup to specific project
    """
    db = SessionLocal()
    
    try:
        # Query all endpoint_new events
        query = db.query(Event).filter(Event.type == EventType.ENDPOINT_NEW)
        
        if project_id:
            query = query.filter(Event.project_id == project_id)
        
        events = query.all()
        print(f"\n📊 Found {len(events)} endpoint_new events to analyze\n")
        
        false_positives = []
        
        for event in events:
            details = event.details or {}
            url = details.get('url', '')
            matched_keywords = details.get('matched_keywords', [])
            
            if is_false_positive(url, matched_keywords):
                false_positives.append({
                    'id': event.id,
                    'url': url,
                    'summary': event.summary,
                    'matched_keywords': matched_keywords,
                    'project_id': event.project_id
                })
        
        print(f"🔍 Found {len(false_positives)} false positive events\n")
        
        if not false_positives:
            print("✅ No false positives found!")
            return
        
        # Show samples
        print("📋 Sample false positives:")
        for fp in false_positives[:10]:
            print(f"  - ID {fp['id']}: {fp['url'][:60]}... (keywords: {fp['matched_keywords']})")
        
        if len(false_positives) > 10:
            print(f"  ... and {len(false_positives) - 10} more\n")
        
        if dry_run:
            print("\n⚠️  DRY RUN - No changes made")
            print(f"   Run with --execute to delete {len(false_positives)} events")
        else:
            # Actually delete
            deleted_count = 0
            for fp in false_positives:
                event = db.query(Event).get(fp['id'])
                if event:
                    db.delete(event)
                    deleted_count += 1
            
            db.commit()
            print(f"\n✅ Deleted {deleted_count} false positive events")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Remove false positive endpoint_new events from database'
    )
    parser.add_argument(
        '--execute', 
        action='store_true', 
        help='Actually delete events (default is dry-run)'
    )
    parser.add_argument(
        '--project-id', 
        type=int, 
        help='Only cleanup events for specific project ID'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🧹 False Positive Cleanup Script")
    print("=" * 60)
    
    cleanup_false_positives(
        dry_run=not args.execute,
        project_id=args.project_id
    )


if __name__ == '__main__':
    main()
