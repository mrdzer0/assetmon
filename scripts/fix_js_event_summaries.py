#!/usr/bin/env python3
"""
Fix JS Secret Event Summaries Script
Updates js_file_new events to new format: full URL + secret types
"""

import re
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal
from app.models import Event, EventType


def fix_js_event_summaries(dry_run: bool = True, project_id: int = None):
    """
    Update js_file_new event summaries to new format
    
    Old: "Secrets detected in JS file: main.js (high risk)"
    New: "Secrets detected in JS file: https://example.com/main.js [aws_access_key, stripe_secret]"
    
    Args:
        dry_run: If True, only show what would be changed without updating
        project_id: Optional project ID to limit to specific project
    """
    db = SessionLocal()
    
    try:
        # Query all js_file_new events
        query = db.query(Event).filter(Event.type == EventType.JS_FILE_NEW)
        
        if project_id:
            query = query.filter(Event.project_id == project_id)
        
        events = query.all()
        print(f"\n📊 Found {len(events)} js_file_new events to analyze\n")
        
        updates = []
        
        for event in events:
            details = event.details or {}
            url = details.get('url', '')
            
            if not url:
                continue
            
            # Check if summary already has new format (contains full URL)
            if url in event.summary and '[' in event.summary:
                continue
            
            # Get secret types from details
            secret_types = details.get('secret_types', [])
            secrets_found = details.get('secrets_found', [])
            
            # Extract types from secrets_found if secret_types is empty
            if not secret_types and secrets_found:
                secret_types = list(set(s.get('type', 'unknown') for s in secrets_found))
            
            if not secret_types:
                secret_types = ['unknown']
            
            # Build types string
            unique_types = list(set(secret_types))
            types_str = ', '.join(unique_types[:3])
            if len(unique_types) > 3:
                types_str += f' +{len(unique_types) - 3} more'
            
            # Build new summary
            new_summary = f"Secrets detected in JS file: {url} [{types_str}]"
            
            updates.append({
                'id': event.id,
                'old_summary': event.summary,
                'new_summary': new_summary,
                'url': url,
                'secret_types': unique_types,
                'project_id': event.project_id
            })
        
        print(f"🔍 Found {len(updates)} events needing summary update\n")
        
        if not updates:
            print("✅ All summaries already have new format!")
            return
        
        # Show samples
        print("📋 Sample updates:")
        for upd in updates[:5]:
            print(f"  - Project {upd['project_id']}, Event {upd['id']}:")
            print(f"    OLD: {upd['old_summary'][:70]}...")
            print(f"    NEW: {upd['new_summary'][:70]}...")
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
        description='Update js_file_new event summaries to new format with full URL and types'
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
    print("🔧 Fix JS Secret Event Summaries Script")
    print("=" * 60)
    
    fix_js_event_summaries(
        dry_run=not args.execute,
        project_id=args.project_id
    )


if __name__ == '__main__':
    main()
