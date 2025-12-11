#!/usr/bin/env python3
"""
Fix Event Summaries Script
Updates endpoint_new events to show full URL in summary instead of just filename
"""

import re
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal
from app.models import Event, EventType


def fix_event_summaries(dry_run: bool = True, project_id: int = None):
    """
    Update endpoint_new event summaries to show full URL
    
    Args:
        dry_run: If True, only show what would be changed without actually updating
        project_id: Optional project ID to limit to specific project
    """
    db = SessionLocal()
    
    try:
        # Query all endpoint_new events
        query = db.query(Event).filter(Event.type == EventType.ENDPOINT_NEW)
        
        if project_id:
            query = query.filter(Event.project_id == project_id)
        
        events = query.all()
        print(f"\n📊 Found {len(events)} endpoint_new events to analyze\n")
        
        updates = []
        
        for event in events:
            details = event.details or {}
            url = details.get('url', '')
            
            if not url:
                continue
            
            # Get status code from details
            status_code = details.get('status_code', '?')
            
            # Check if summary already has the new format with status code
            # New format: "Sensitive endpoint accessible: {url} [{categories}] [{status}]"
            # Check for status code pattern at end: [200], [301], etc.
            has_status_code = re.search(r'\[\d+\]$', event.summary) or re.search(r'\[\?\]$', event.summary)
            
            if has_status_code:
                continue
            
            # Extract the category part from existing summary
            # Format: "Sensitive endpoint accessible: filename [categories]"
            match = re.search(r'\[([^\]]+)\]', event.summary)
            categories_str = match.group(1) if match else 'unknown'
            
            # Build new summary with full URL and status code
            new_summary = f"Sensitive endpoint accessible: {url} [{categories_str}] [{status_code}]"
            
            updates.append({
                'id': event.id,
                'old_summary': event.summary,
                'new_summary': new_summary,
                'url': url,
                'project_id': event.project_id
            })
        
        print(f"🔍 Found {len(updates)} events needing summary update\n")
        
        if not updates:
            print("✅ All summaries already have full URLs!")
            return
        
        # Show samples
        print("📋 Sample updates:")
        for upd in updates[:5]:
            print(f"  - Project {upd['project_id']}, Event {upd['id']}:")
            print(f"    OLD: {upd['old_summary'][:60]}...")
            print(f"    NEW: {upd['new_summary'][:60]}...")
            print()
        
        if len(updates) > 5:
            print(f"  ... and {len(updates) - 5} more\n")
        
        if dry_run:
            print("\n⚠️  DRY RUN - No changes made")
            print(f"   Run with --execute to update {len(updates)} events")
        else:
            # Actually update
            updated_count = 0
            for upd in updates:
                event = db.query(Event).get(upd['id'])
                if event:
                    event.summary = upd['new_summary']
                    updated_count += 1
            
            db.commit()
            print(f"\n✅ Updated {updated_count} event summaries")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Update endpoint_new event summaries to show full URL'
    )
    parser.add_argument(
        '--execute', 
        action='store_true', 
        help='Actually update events (default is dry-run)'
    )
    parser.add_argument(
        '--project-id', 
        type=int, 
        help='Only update events for specific project ID'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔧 Fix Event Summaries Script")
    print("=" * 60)
    
    fix_event_summaries(
        dry_run=not args.execute,
        project_id=args.project_id
    )


if __name__ == '__main__':
    main()
