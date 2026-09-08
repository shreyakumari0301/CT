#!/usr/bin/env python3
"""
Pre-compute embeddings for B2F corpus to improve performance
This script pre-computes and caches embeddings for all corpus entries,
creating three cache files: xxx_corpus.pkl, xxx_embeddings.pkl, and xxx_index.faiss
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))
from utils.embedding_utils import create_embedding_manager
from config.settings import *

def load_corpus(corpus_file: str) -> List[Dict[str, Any]]:
    """Load corpus from file"""
    print(f"📁 Loading corpus from: {corpus_file}")
    
    if not Path(corpus_file).exists():
        print(f"❌ Corpus file not found: {corpus_file}")
        return []
    
    corpus_entries = []
    try:
        with open(corpus_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line.strip())
                    entry_id = entry.get('id', '')
                    if entry_id:
                        corpus_entries.append({
                            'id': entry_id,
                            'title': entry.get('title', ''),
                            'contents': entry.get('contents', ''),
                            'name': entry.get('name', ''),
                            'description': entry.get('description', '')
                        })
        
        print(f"✅ Loaded {len(corpus_entries)} entries from corpus")
        return corpus_entries
        
    except Exception as e:
        print(f"❌ Error loading corpus: {e}")
        return []

def precompute_mitre_embeddings():
    """Pre-compute embeddings for MITRE corpus"""
    print("🚀 Pre-computing MITRE corpus embeddings...")
    
    # Load MITRE corpus
    corpus_entries = load_corpus(MITRE_CORPUS_FILE)
    if not corpus_entries:
        print("❌ Failed to load MITRE corpus")
        return False
    
    # Create embedding manager
    embedding_manager = create_embedding_manager()
    
    # Pre-compute embeddings
    success = embedding_manager.precompute_corpus_embeddings(
        corpus_entries, 
        framework="mitre",
        text_field='contents'
    )
    
    if success:
        print("✅ MITRE corpus embeddings pre-computed successfully")
        print("📁 Cache files created:")
        print("   - mitre_corpus.pkl")
        print("   - mitre_embeddings.pkl")
        print("   - mitre_index.faiss")
    else:
        print("❌ Failed to pre-compute MITRE corpus embeddings")
    
    return success

def precompute_cwe_embeddings():
    """Pre-compute embeddings for CWE corpus"""
    print("🚀 Pre-computing CWE corpus embeddings...")
    
    # Load CWE corpus
    corpus_entries = load_corpus(CWE_CORPUS_FILE)
    if not corpus_entries:
        print("❌ Failed to load CWE corpus")
        return False
    
    # Create embedding manager
    embedding_manager = create_embedding_manager()
    
    # Pre-compute embeddings
    success = embedding_manager.precompute_corpus_embeddings(
        corpus_entries, 
        framework="cwe",
        text_field='description'
    )
    
    if success:
        print("✅ CWE corpus embeddings pre-computed successfully")
        print("📁 Cache files created:")
        print("   - cwe_corpus.pkl")
        print("   - cwe_embeddings.pkl")
        print("   - cwe_index.faiss")
    else:
        print("❌ Failed to pre-compute CWE corpus embeddings")
    
    return success

def show_cache_status():
    """Show current cache status"""
    print("📊 Current Cache Status:")
    print("=" * 50)
    
    cache_dir = Path(EMBEDDING_CACHE)
    if not cache_dir.exists():
        print("❌ Cache directory does not exist")
        return
    
    # Check MITRE cache
    mitre_files = [
        cache_dir / "mitre_corpus.pkl",
        cache_dir / "mitre_embeddings.pkl",
        cache_dir / "mitre_index.faiss"
    ]
    
    print("🔍 MITRE Framework:")
    for file_path in mitre_files:
        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"   ✅ {file_path.name} ({size_mb:.1f} MB)")
        else:
            print(f"   ❌ {file_path.name} (missing)")
    
    # Check CWE cache
    cwe_files = [
        cache_dir / "cwe_corpus.pkl",
        cache_dir / "cwe_embeddings.pkl",
        cache_dir / "cwe_index.faiss"
    ]
    
    print("\n🔍 CWE Framework:")
    for file_path in cwe_files:
        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"   ✅ {file_path.name} ({size_mb:.1f} MB)")
        else:
            print(f"   ❌ {file_path.name} (missing)")
    
    # Check for old cache files
    old_files = []
    for file_path in cache_dir.glob("*"):
        if file_path.is_file() and not any(pattern in file_path.name for pattern in ["_corpus.pkl", "_embeddings.pkl", "_index.faiss"]):
            old_files.append(file_path)
    
    if old_files:
        print(f"\n⚠️  Old cache files found ({len(old_files)} files):")
        for file_path in old_files:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"   📁 {file_path.name} ({size_mb:.1f} MB)")

def clear_cache(framework: str = None):
    """Clear cache for specific framework or all frameworks"""
    print("🧹 Clearing cache...")
    
    embedding_manager = create_embedding_manager()
    embedding_manager.clear_cache(framework)
    
    if framework:
        print(f"✅ Cleared cache for {framework} framework")
    else:
        print("✅ Cleared all cache")

def main():
    """Main function"""
    print("🎯 B2F Repository - Pre-compute Corpus Embeddings")
    print("=" * 60)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "mitre":
            precompute_mitre_embeddings()
        elif command == "cwe":
            precompute_cwe_embeddings()
        elif command == "status":
            show_cache_status()
        elif command == "clear":
            framework = sys.argv[2] if len(sys.argv) > 2 else None
            clear_cache(framework)
        elif command == "help":
            print("Usage:")
            print("  python precompute_embeddings.py mitre     # Pre-compute MITRE embeddings")
            print("  python precompute_embeddings.py cwe       # Pre-compute CWE embeddings")
            print("  python precompute_embeddings.py status    # Show cache status")
            print("  python precompute_embeddings.py clear     # Clear all cache")
            print("  python precompute_embeddings.py clear mitre  # Clear MITRE cache only")
            print("  python precompute_embeddings.py clear cwe    # Clear CWE cache only")
        else:
            print(f"❌ Unknown command: {command}")
            print("Use 'python precompute_embeddings.py help' for usage information")
            sys.exit(1)
    else:
        # Pre-compute both frameworks
        print("🔄 Pre-computing embeddings for both MITRE and CWE frameworks...")
        
        mitre_success = precompute_mitre_embeddings()
        print()
        cwe_success = precompute_cwe_embeddings()
        
        if mitre_success and cwe_success:
            print("\n🎉 All corpus embeddings pre-computed successfully!")
            print("\n📁 Cache structure created:")
            print("   - mitre_corpus.pkl, mitre_embeddings.pkl, mitre_index.faiss")
            print("   - cwe_corpus.pkl, cwe_embeddings.pkl, cwe_index.faiss")
        else:
            print("\n⚠️  Some corpus embeddings failed to pre-compute")
            sys.exit(1)

if __name__ == "__main__":
    main()
