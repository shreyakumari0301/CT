#!/usr/bin/env python3
"""
B2F Repository Main Entry Point

Integrates three core modules:
1. Blog Digger - AI-powered blog analysis
2. Behavior Annotator - Add behavior_id to CWE/MITRE entries
3. LLM Annotator - LLM-powered CWE/MITRE annotation
"""

import sys
import argparse
from pathlib import Path

# Add core directory to path for imports
sys.path.append(str(Path(__file__).parent / "core"))

from blog_digger import BlogDigger
from behavior_annotator import BehaviorAnnotator
from llm_annotator import LLMAnnotator

def run_blog_digger(limit: int = None, model: str = None, framework: str = "cwe") -> bool:
    """Run the blog digger module"""
    print("\n" + "="*60)
    print(f"🚀 B2F Blog Digger ({framework.upper()})")
    print("="*60)
    
    try:
        digger = BlogDigger(model_name=model, framework=framework)
        success = digger.process_all_blogs(limit=limit)
        return success
    except Exception as e:
        print(f"❌ Blog Digger failed: {e}")
        return False

def run_behavior_annotator(framework: str = "cwe") -> bool:
    """Run the behavior annotator module"""
    print("\n" + "="*60)
    print(f"🚀 B2F Behavior Annotator ({framework.upper()})")
    print("="*60)
    
    try:
        annotator = BehaviorAnnotator(framework=framework)
        success = annotator.run()
        return success
    except Exception as e:
        print(f"❌ Behavior Annotator failed: {e}")
        return False

def run_llm_annotator(limit: int = None, framework: str = "cwe", force_restart: bool = False) -> bool:
    """Run the LLM annotator module"""
    print("\n" + "="*60)
    print(f"🚀 B2F LLM Annotator ({framework.upper()})")
    print("="*60)
    
    try:
        annotator = LLMAnnotator(framework=framework, force_restart=force_restart)
        success = annotator.run(limit=limit)
        return success
    except Exception as e:
        print(f"❌ LLM Annotator failed: {e}")
        return False

def run_full_pipeline(limit: int = None, model: str = None, framework: str = "cwe", force_restart: bool = False) -> bool:
    """Run the complete B2F pipeline"""
    print("\n" + "="*60)
    print(f"🚀 B2F Complete Pipeline ({framework.upper()})")
    print("="*60)
    
    # Step 1: Blog Digger
    print(f"\n📝 Step 1: Blog Analysis ({framework.upper()})")
    if not run_blog_digger(limit=limit, model=model, framework=framework):
        print("❌ Blog Digger failed, stopping pipeline")
        return False
    
    # Step 2: Behavior Annotator
    print(f"\n📝 Step 2: Behavior ID Assignment ({framework.upper()})")
    if not run_behavior_annotator(framework=framework):
        print("❌ Behavior Annotator failed, stopping pipeline")
        return False
    
    # Step 3: LLM Annotator
    print(f"\n📝 Step 3: LLM Annotation ({framework.upper()})")
    if not run_llm_annotator(limit=limit, framework=framework, force_restart=force_restart):
        print("❌ LLM Annotator failed, stopping pipeline")
        return False
    
    print(f"\n🎉 B2F Complete Pipeline finished successfully for {framework.upper()}!")
    return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="B2F Repository - Blog to Framework Data Processing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline for CWE (default)
  python main.py --mode full
  
  # Run complete pipeline for MITRE
  python main.py --mode full --framework mitre
  
  # Run only blog analysis for MITRE
  python main.py --mode blog --framework mitre --limit 10
  
  # Run only behavior annotation for CWE
  python main.py --mode behavior --framework cwe
  
  # Run only LLM annotation for MITRE
  python main.py --mode llm --framework mitre --limit 5
  
  # Force restart annotation process (ignore checkpoints)
  python main.py --mode llm --framework mitre --force-restart
  
  # Run complete pipeline with force restart
  python main.py --mode full --framework mitre --force-restart
        """
    )
    
    parser.add_argument(
        "--mode", 
        type=str, 
        default="full",
        choices=["full", "blog", "behavior", "llm"],
        help="Processing mode (default: full)"
    )
    
    parser.add_argument(
        "--framework",
        type=str,
        default="cwe",
        choices=["cwe", "mitre", "capec", "cve"],
        help="Framework to use: cwe, mitre, capec, or cve (default: cwe)"
    )
    
    parser.add_argument(
        "--limit", 
        type=int, 
        help="Number of blog entries to process"
    )
    
    parser.add_argument(
        "--model", 
        type=str, 
        help="LLM model to use (default: from config)"
    )
    
    parser.add_argument(
        "--force-restart",
        action="store_true",
        help="Force restart annotation process (ignore existing checkpoints)"
    )
    
    args = parser.parse_args()
    
    print("🎯 B2F Repository - Blog to Framework")
    print("="*60)
    print(f"Mode: {args.mode.upper()}")
    print(f"Framework: {args.framework.upper()}")
    if args.limit:
        print(f"Limit: {args.limit} entries")
    if args.model:
        print(f"Model: {args.model}")
    if args.force_restart:
        print("🔄 Force restart enabled")
    print("="*60)
    
    # Run selected mode
    success = False
    
    if args.mode == "full":
        success = run_full_pipeline(limit=args.limit, model=args.model, framework=args.framework, force_restart=args.force_restart)
    elif args.mode == "blog":
        success = run_blog_digger(limit=args.limit, model=args.model, framework=args.framework)
    elif args.mode == "behavior":
        success = run_behavior_annotator(framework=args.framework)
    elif args.mode == "llm":
        success = run_llm_annotator(limit=args.limit, framework=args.framework, force_restart=args.force_restart)
    
    # Final status
    if success:
        print(f"\n🎉 B2F Repository completed successfully for {args.framework.upper()}!")
        print("\n📁 Output files:")
        
        if args.framework == "mitre":
            from config.settings import BLOG_MITRE_FILTERED, BLOG_MITRE_BEHAVIOR_ID, BLOG_MITRE_LLM_ENRICHED
            print(f"  - Blog analysis: {BLOG_MITRE_FILTERED}")
            print(f"  - Behavior IDs: {BLOG_MITRE_BEHAVIOR_ID}")
            print(f"  - LLM annotations: {BLOG_MITRE_LLM_ENRICHED}")
        elif args.framework == "capec":
            from config.settings import BLOG_CAPEC_FILTERED, BLOG_CAPEC_BEHAVIOR_ID, BLOG_CAPEC_LLM_ENRICHED
            print(f"  - Blog analysis: {BLOG_CAPEC_FILTERED}")
            print(f"  - Behavior IDs: {BLOG_CAPEC_BEHAVIOR_ID}")
            print(f"  - LLM annotations: {BLOG_CAPEC_LLM_ENRICHED}")
        elif args.framework == "cve":
            from config.settings import BLOG_CVE_FILTERED, BLOG_CVE_BEHAVIOR_ID, BLOG_CVE_LLM_ENRICHED
            print(f"  - Blog analysis: {BLOG_CVE_FILTERED}")
            print(f"  - Behavior IDs: {BLOG_CVE_BEHAVIOR_ID}")
            print(f"  - LLM annotations: {BLOG_CVE_LLM_ENRICHED}")
        else:  # cwe
            from config.settings import BLOG_CWE_FILTERED, BLOG_CWE_BEHAVIOR_ID, BLOG_CWE_LLM_ENRICHED
            print(f"  - Blog analysis: {BLOG_CWE_FILTERED}")
            print(f"  - Behavior IDs: {BLOG_CWE_BEHAVIOR_ID}")
            print(f"  - LLM annotations: {BLOG_CWE_LLM_ENRICHED}")
    else:
        print("\n❌ B2F Repository encountered errors")
        sys.exit(1)

if __name__ == "__main__":
    main()
