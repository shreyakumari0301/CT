#!/usr/bin/env python3
"""
Behavior Annotator - Add behavior_id to CWE or MITRE entries for B2F repository
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))
from utils.file_utils import load_jsonl, save_jsonl, file_exists, get_file_size
from config.settings import *

class BehaviorAnnotator:
    """Add behavior_id to CWE or MITRE entries in blog data"""
    
    def __init__(self, framework: str = "cwe"):
        """Initialize the behavior annotator"""
        self.framework = framework.lower()
        
        if self.framework == "mitre":
            self.input_file = BLOG_MITRE_FILTERED
            self.output_file = BLOG_MITRE_BEHAVIOR_ID
        elif self.framework == "capec":
            self.input_file = BLOG_CAPEC_FILTERED
            self.output_file = BLOG_CAPEC_BEHAVIOR_ID
        elif self.framework == "cve":
            self.input_file = BLOG_CVE_FILTERED
            self.output_file = BLOG_CVE_BEHAVIOR_ID
        else:  # cwe (default)
            self.input_file = BLOG_CWE_FILTERED
            self.output_file = BLOG_CWE_BEHAVIOR_ID
        
        print(f"📁 Framework: {self.framework.upper()}")
        print(f"📁 Input file: {self.input_file}")
        print(f"📁 Output file: {self.output_file}")
    
    def add_behavior_ids(self) -> bool:
        """Add behavior_id to each entry"""
        print(f"🚀 Adding behavior_id to {self.framework.upper()} entries...")
        
        # Check if input file exists
        if not file_exists(str(self.input_file)):
            print(f"❌ Input file not found: {self.input_file}")
            return False
        
        processed_count = 0
        total_entries_count = 0
        
        try:
            # Load input data
            blog_entries = load_jsonl(str(self.input_file))
            if not blog_entries:
                print("❌ No data loaded from input file")
                return False
            
            # Process each blog entry
            for blog_entry in blog_entries:
                if self.framework == "mitre":
                    entries = blog_entry.get('techniques', [])  # Changed from 'technique_entries'
                elif self.framework == "capec":
                    entries = blog_entry.get('capec_entries', [])
                elif self.framework == "cve":
                    entries = blog_entry.get('cve_entries', [])
                else:  # cwe
                    entries = blog_entry.get('cwe_entries', [])
                
                # Add behavior_id to each entry
                for entry_index, entry in enumerate(entries):
                    entry['behavior_id'] = entry_index
                    total_entries_count += 1
                
                processed_count += 1
                
                if processed_count % 10 == 0:
                    print(f"  Processed {processed_count} blog entries...")
            
            # Save processed data
            if save_jsonl(blog_entries, str(self.output_file)):
                print(f"✅ Successfully processed {processed_count} blog entries")
                print(f"📊 Added behavior_id to {total_entries_count} {self.framework.upper()} entries")
                print(f"💾 Output saved to: {self.output_file}")
                
                # Show file sizes
                input_size = get_file_size(str(self.input_file))
                output_size = get_file_size(str(self.output_file))
                print(f"📊 File sizes:")
                print(f"  Input:  {input_size:.2f} MB")
                print(f"  Output: {output_size:.2f} MB")
                
                return True
            else:
                print("❌ Failed to save output file")
                return False
                
        except Exception as e:
            print(f"❌ Error processing file: {e}")
            return False
    
    def verify_output(self) -> bool:
        """Verify the output file by checking behavior_id assignment"""
        print(f"\n🔍 Verifying behavior_id assignment...")
        
        if not file_exists(str(self.output_file)):
            print(f"❌ Output file not found: {self.output_file}")
            return False
        
        try:
            blog_entries = load_jsonl(str(self.output_file))
            
            # Statistics
            total_blogs = len(blog_entries)
            total_entries = 0
            issues = []
            
            for blog_entry in blog_entries:
                blog_id = blog_entry.get('blog_id')
                
                if self.framework == "mitre":
                    entries = blog_entry.get('techniques', [])  # Changed from 'technique_entries'
                    entry_type = "technique"
                elif self.framework == "capec":
                    entries = blog_entry.get('capec_entries', [])
                    entry_type = "CAPEC"
                elif self.framework == "cve":
                    entries = blog_entry.get('cve_entries', [])
                    entry_type = "CVE"
                else:  # cwe
                    entries = blog_entry.get('cwe_entries', [])
                    entry_type = "CWE"
                
                # Check each entry
                for entry_index, entry in enumerate(entries):
                    total_entries += 1
                    
                    # Check if behavior_id exists and is correct
                    behavior_id = entry.get('behavior_id')
                    if behavior_id is None:
                        issues.append(f"Blog {blog_id}: Missing behavior_id for {entry_type} {entry.get('technique_id' if self.framework == 'mitre' else 'cwe_id', 'unknown')}")
                    elif not isinstance(behavior_id, int):
                        issues.append(f"Blog {blog_id}: behavior_id is not integer. Got {type(behavior_id)}: {behavior_id}")
                    elif behavior_id != entry_index:
                        issues.append(f"Blog {blog_id}: Incorrect behavior_id. Expected {entry_index}, got {behavior_id}")
                    
                    # Check required fields based on framework
                    if self.framework == "mitre":
                        if not entry.get('technique_id'):
                            issues.append(f"Blog {blog_id}: Missing technique_id")
                        if not entry.get('technique_name'):
                            issues.append(f"Blog {blog_id}: Missing technique_name")
                        if not entry.get('attack_behavior_text'):  # Changed from 'attack_behaviors'
                            issues.append(f"Blog {blog_id}: Missing attack_behavior_text")
                    elif self.framework == "capec":
                        if not entry.get('capec_id'):
                            issues.append(f"Blog {blog_id}: Missing capec_id")
                        if not entry.get('capec_name'):
                            issues.append(f"Blog {blog_id}: Missing capec_name")
                        if not entry.get('attack_patterns'):
                            issues.append(f"Blog {blog_id}: Missing attack_patterns")
                    elif self.framework == "cve":
                        if not entry.get('cve_id'):
                            issues.append(f"Blog {blog_id}: Missing cve_id")
                        if not entry.get('cve_description'):
                            issues.append(f"Blog {blog_id}: Missing cve_description")
                        if not entry.get('exploit_contexts'):
                            issues.append(f"Blog {blog_id}: Missing exploit_contexts")
                    else:  # cwe
                        if not entry.get('cwe_id'):
                            issues.append(f"Blog {blog_id}: Missing cwe_id")
                        if not entry.get('cwe_name'):
                            issues.append(f"Blog {blog_id}: Missing cwe_name")
                        if not entry.get('vulnerabilities'):
                            issues.append(f"Blog {blog_id}: Missing vulnerabilities")
            
            # Print verification results
            print(f"✅ Verification completed!")
            print(f"📊 Statistics:")
            print(f"  Total blogs: {total_blogs}")
            print(f"  Total {self.framework.upper()} entries: {total_entries}")
            
            # Report issues
            if issues:
                print(f"\n❌ Issues found ({len(issues)}):")
                for issue in issues[:10]:  # Show first 10 issues
                    print(f"  {issue}")
                if len(issues) > 10:
                    print(f"  ... and {len(issues) - 10} more issues")
                return False
            else:
                print(f"\n✅ No issues found! All behavior_ids are correctly assigned.")
                return True
                
        except Exception as e:
            print(f"❌ Error during verification: {e}")
            return False
    
    def run(self) -> bool:
        """Run the complete behavior annotation process"""
        print("=" * 50)
        print(f"B2F Behavior Annotator ({self.framework.upper()})")
        print("=" * 50)
        
        # Add behavior_ids
        success = self.add_behavior_ids()
        
        if success:
            # Verify the output
            verification_success = self.verify_output()
            
            if verification_success:
                print(f"\n🎉 Behavior annotation completed successfully for {self.framework.upper()}!")
                return True
            else:
                print(f"\n⚠️  Behavior annotation completed but verification failed!")
                return False
        else:
            print(f"\n❌ Behavior annotation failed!")
            return False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="B2F Behavior Annotator - Add behavior_id to entries")
    parser.add_argument("--framework", type=str, default="cwe", choices=["cwe", "mitre", "capec", "cve"], 
                       help="Framework to use: cwe, mitre, capec, or cve (default: cwe)")
    
    args = parser.parse_args()
    
    try:
        annotator = BehaviorAnnotator(framework=args.framework)
        success = annotator.run()
        
        if success:
            print(f"\n🎉 B2F Behavior Annotator completed successfully for {args.framework.upper()}!")
        else:
            print(f"\n❌ B2F Behavior Annotator encountered errors")
            
    except Exception as e:
        print(f"❌ Failed to initialize B2F Behavior Annotator: {e}")

if __name__ == "__main__":
    main()
