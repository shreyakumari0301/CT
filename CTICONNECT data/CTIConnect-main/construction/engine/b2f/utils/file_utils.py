"""
File utility functions for B2F repository
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

def load_jsonl(file_path: str) -> List[Dict[str, Any]]:
    """Load data from JSONL file"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    try:
                        entry = json.loads(line.strip())
                        data.append(entry)
                    except json.JSONDecodeError as e:
                        print(f"⚠️  Warning: Invalid JSON on line {line_num}: {e}")
                        continue
        print(f"✅ Loaded {len(data)} entries from {file_path}")
        return data
    except Exception as e:
        print(f"❌ Error loading {file_path}: {e}")
        return []

def save_jsonl(data: List[Dict[str, Any]], file_path: str, mode: str = 'w') -> bool:
    """Save data to JSONL file"""
    try:
        # Ensure output directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, mode, encoding='utf-8') as f:
            for entry in data:
                json.dump(entry, f, ensure_ascii=False)
                f.write('\n')
        
        print(f"✅ Saved {len(data)} entries to {file_path}")
        return True
    except Exception as e:
        print(f"❌ Error saving to {file_path}: {e}")
        return False

def append_jsonl(data: List[Dict[str, Any]], file_path: str) -> bool:
    """Append data to existing JSONL file"""
    return save_jsonl(data, file_path, mode='a')

def file_exists(file_path: str) -> bool:
    """Check if file exists"""
    return Path(file_path).exists()

def get_file_size(file_path: str) -> float:
    """Get file size in MB"""
    if file_exists(file_path):
        return Path(file_path).stat().st_size / 1024 / 1024
    return 0.0

def ensure_dir(dir_path: str) -> None:
    """Ensure directory exists"""
    Path(dir_path).mkdir(parents=True, exist_ok=True)
