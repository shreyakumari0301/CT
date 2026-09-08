#!/usr/bin/env python3
"""
Checkpoint Manager for B2F LLM Annotator

This script provides utilities to manage checkpoints for the LLM annotation process.
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))
from config.settings import *

def get_checkpoint_files() -> Dict[str, Path]:
    """Get checkpoint file paths for both frameworks"""
    cache_dir = Path(CHECKPOINT_FILE).parent
    return {
        'cwe': cache_dir / "llm_annotator_cwe.json",
        'mitre': cache_dir / "llm_annotator_mitre.json"
    }

def show_checkpoint_status(framework: str = None):
    """Show checkpoint status for specified framework or all frameworks"""
    checkpoint_files = get_checkpoint_files()
    
    if framework:
        frameworks = [framework]
    else:
        frameworks = ['cwe', 'mitre']
    
    print("📊 Checkpoint Status")
    print("=" * 60)
    
    for fw in frameworks:
        if fw not in checkpoint_files:
            print(f"❌ Framework '{fw}' not supported")
            continue
            
        checkpoint_file = checkpoint_files[fw]
        print(f"\n🔍 {fw.upper()} Framework:")
        print("-" * 30)
        
        if not checkpoint_file.exists():
            print("   ❌ No checkpoint file found")
            continue
        
        try:
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)
            
            print(f"   ✅ Checkpoint file: {checkpoint_file.name}")
            print(f"   📁 Status: {checkpoint.get('status', 'unknown')}")
            print(f"   📊 Total blogs processed: {checkpoint.get('total_blogs_processed', 0)}")
            print(f"   📊 Total annotations generated: {checkpoint.get('total_annotations_generated', 0)}")
            
            if checkpoint.get('last_processed_blog_id'):
                print(f"   🎯 Last processed blog: {checkpoint.get('last_processed_blog_id')}")
                if checkpoint.get('last_processed_behavior_id') is not None:
                    print(f"   🎯 Last processed behavior: {checkpoint.get('last_processed_behavior_id')}")
            
            if checkpoint.get('start_time'):
                start_time = datetime.fromisoformat(checkpoint['start_time'])
                print(f"   🕐 Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if checkpoint.get('last_update'):
                last_update = datetime.fromisoformat(checkpoint['last_update'])
                print(f"   🕐 Last update: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")
                
        except Exception as e:
            print(f"   ❌ Error reading checkpoint: {e}")

def clear_checkpoint(framework: str, confirm: bool = False):
    """Clear checkpoint for specified framework"""
    checkpoint_files = get_checkpoint_files()
    
    if framework not in checkpoint_files:
        print(f"❌ Framework '{framework}' not supported")
        return False
    
    checkpoint_file = checkpoint_files[framework]
    
    if not checkpoint_file.exists():
        print(f"✅ No checkpoint file found for {framework.upper()}")
        return True
    
    if not confirm:
        print(f"⚠️  This will delete the checkpoint file for {framework.upper()}")
        print(f"   File: {checkpoint_file}")
        response = input("   Are you sure? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Operation cancelled")
            return False
    
    try:
        checkpoint_file.unlink()
        print(f"✅ Checkpoint cleared for {framework.upper()}")
        return True
    except Exception as e:
        print(f"❌ Error clearing checkpoint: {e}")
        return False

def reset_checkpoint(framework: str, confirm: bool = False):
    """Reset checkpoint to initial state for specified framework"""
    checkpoint_files = get_checkpoint_files()
    
    if framework not in checkpoint_files:
        print(f"❌ Framework '{framework}' not supported")
        return False
    
    checkpoint_file = checkpoint_files[framework]
    
    if not confirm:
        print(f"⚠️  This will reset the checkpoint for {framework.upper()} to initial state")
        print(f"   File: {checkpoint_file}")
        response = input("   Are you sure? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Operation cancelled")
            return False
    
    try:
        # Create initial checkpoint state
        initial_state = {
            'framework': framework,
            'last_processed_blog_id': None,
            'last_processed_behavior_id': None,
            'total_blogs_processed': 0,
            'total_annotations_generated': 0,
            'start_time': datetime.now().isoformat(),
            'last_update': datetime.now().isoformat(),
            'status': 'initialized'
        }
        
        # Ensure checkpoint directory exists
        checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(checkpoint_file, 'w', encoding='utf-8') as f:
            json.dump(initial_state, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Checkpoint reset for {framework.upper()}")
        return True
        
    except Exception as e:
        print(f"❌ Error resetting checkpoint: {e}")
        return False

def backup_checkpoint(framework: str):
    """Create a backup of the checkpoint file"""
    checkpoint_files = get_checkpoint_files()
    
    if framework not in checkpoint_files:
        print(f"❌ Framework '{framework}' not supported")
        return False
    
    checkpoint_file = checkpoint_files[framework]
    
    if not checkpoint_file.exists():
        print(f"❌ No checkpoint file found for {framework.upper()}")
        return False
    
    try:
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = checkpoint_file.parent / f"{checkpoint_file.stem}_backup_{timestamp}.json"
        
        # Copy checkpoint file
        import shutil
        shutil.copy2(checkpoint_file, backup_file)
        
        print(f"✅ Checkpoint backed up to: {backup_file.name}")
        return True
        
    except Exception as e:
        print(f"❌ Error backing up checkpoint: {e}")
        return False

def restore_checkpoint(framework: str, backup_file: str, confirm: bool = False):
    """Restore checkpoint from backup file"""
    checkpoint_files = get_checkpoint_files()
    
    if framework not in checkpoint_files:
        print(f"❌ Framework '{framework}' not supported")
        return False
    
    checkpoint_file = checkpoint_files[framework]
    backup_path = Path(backup_file)
    
    if not backup_path.exists():
        print(f"❌ Backup file not found: {backup_file}")
        return False
    
    if not confirm:
        print(f"⚠️  This will restore the checkpoint for {framework.upper()} from backup")
        print(f"   Backup: {backup_file}")
        print(f"   Target: {checkpoint_file}")
        response = input("   Are you sure? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Operation cancelled")
            return False
    
    try:
        # Validate backup file
        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        if backup_data.get('framework') != framework:
            print(f"❌ Backup file framework mismatch. Expected {framework}, got {backup_data.get('framework')}")
            return False
        
        # Restore checkpoint
        import shutil
        shutil.copy2(backup_path, checkpoint_file)
        
        print(f"✅ Checkpoint restored for {framework.upper()}")
        return True
        
    except Exception as e:
        print(f"❌ Error restoring checkpoint: {e}")
        return False

def list_backups():
    """List available backup files"""
    checkpoint_files = get_checkpoint_files()
    cache_dir = Path(CHECKPOINT_FILE).parent
    
    print("📁 Available Backup Files")
    print("=" * 60)
    
    for framework in ['cwe', 'mitre']:
        print(f"\n🔍 {framework.upper()} Framework:")
        print("-" * 30)
        
        # Find backup files for this framework
        backup_files = list(cache_dir.glob(f"llm_annotator_{framework}_backup_*.json"))
        
        if not backup_files:
            print("   ❌ No backup files found")
            continue
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        for backup_file in backup_files:
            stat = backup_file.stat()
            size_mb = stat.st_size / (1024 * 1024)
            mod_time = datetime.fromtimestamp(stat.st_mtime)
            
            print(f"   📁 {backup_file.name}")
            print(f"      Size: {size_mb:.2f} MB")
            print(f"      Modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="B2F Checkpoint Manager - Manage LLM annotation checkpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show status of all checkpoints
  python manage_checkpoints.py status
  
  # Show status of specific framework
  python manage_checkpoints.py status --framework mitre
  
  # Clear checkpoint for CWE
  python manage_checkpoints.py clear --framework cwe
  
  # Reset checkpoint for MITRE
  python manage_checkpoints.py reset --framework mitre
  
  # Backup checkpoint for CWE
  python manage_checkpoints.py backup --framework cwe
  
  # List available backups
  python manage_checkpoints.py list-backups
  
  # Restore checkpoint from backup
  python manage_checkpoints.py restore --framework mitre --backup-file backup.json
        """
    )
    
    parser.add_argument(
        "command",
        choices=["status", "clear", "reset", "backup", "restore", "list-backups"],
        help="Command to execute"
    )
    
    parser.add_argument(
        "--framework",
        choices=["cwe", "mitre"],
        help="Framework to operate on (required for clear, reset, backup, restore)"
    )
    
    parser.add_argument(
        "--backup-file",
        help="Backup file path (required for restore command)"
    )
    
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Skip confirmation prompts"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.command in ["clear", "reset", "backup"] and not args.framework:
        print("❌ Error: --framework is required for this command")
        sys.exit(1)
    
    if args.command == "restore" and (not args.framework or not args.backup_file):
        print("❌ Error: --framework and --backup-file are required for restore command")
        sys.exit(1)
    
    # Execute command
    success = False
    
    if args.command == "status":
        show_checkpoint_status(args.framework)
        success = True
    
    elif args.command == "clear":
        success = clear_checkpoint(args.framework, args.confirm)
    
    elif args.command == "reset":
        success = reset_checkpoint(args.framework, args.confirm)
    
    elif args.command == "backup":
        success = backup_checkpoint(args.framework)
    
    elif args.command == "restore":
        success = restore_checkpoint(args.framework, args.backup_file, args.confirm)
    
    elif args.command == "list-backups":
        list_backups()
        success = True
    
    # Exit with appropriate code
    if success:
        print("\n✅ Operation completed successfully")
        sys.exit(0)
    else:
        print("\n❌ Operation failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
