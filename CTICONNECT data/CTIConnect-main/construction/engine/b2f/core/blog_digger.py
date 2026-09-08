#!/usr/bin/env python3
"""
Blog Digger - Core AI-powered blog processor for B2F repository
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))
from utils.file_utils import load_jsonl, save_jsonl, file_exists
from utils.llm_utils import setup_openai_client, call_llm_api, count_tokens, truncate_text
from config.settings import *

class BlogDigger:
    """AI-powered blog processor for extracting CWE or MITRE information"""
    
    def __init__(self, model_name: str = None, framework: str = "cwe"):
        """Initialize the blog digger"""
        self.model_name = model_name or LLM_MODEL
        self.framework = framework.lower()
        self.client = setup_openai_client()
        self.setup_paths()
        
        # Token allocation based on model
        if model_name == "gpt-5":
            self.max_input_tokens = 120000
            self.max_output_tokens = 8000
        elif model_name == "gpt-4o-mini":
            self.max_input_tokens = 16384
            self.max_output_tokens = 4000
        else:  # o3-mini and others
            self.max_input_tokens = MAX_INPUT_TOKENS
            self.max_output_tokens = MAX_OUTPUT_TOKENS
    
    def setup_paths(self):
        """Setup input and output file paths based on framework"""
        self.input_file = BLOG_INPUT_FILE
        
        if self.framework == "mitre":
            self.output_file = BLOG_MITRE_OUTPUT
            self.filtered_output_file = BLOG_MITRE_FILTERED
            self.corpus_file = MITRE_CORPUS_FILE
        elif self.framework == "capec":
            self.output_file = BLOG_CAPEC_OUTPUT
            self.filtered_output_file = BLOG_CAPEC_FILTERED
            self.corpus_file = CAPEC_CORPUS_FILE
        elif self.framework == "cve":
            self.output_file = BLOG_CVE_OUTPUT
            self.filtered_output_file = BLOG_CVE_FILTERED
            self.corpus_file = CVE_CORPUS_FILE
        else:  # cwe (default)
            self.output_file = BLOG_CWE_OUTPUT
            self.filtered_output_file = BLOG_CWE_FILTERED
            self.corpus_file = CWE_CORPUS_FILE
        
        print(f"📁 Framework: {self.framework.upper()}")
        print(f"📁 Input file: {self.input_file}")
        print(f"📁 Corpus file: {self.corpus_file}")
        print(f"📁 Output file: {self.output_file}")
        print(f"📁 Filtered output: {self.filtered_output_file}")
    
    def get_cwe_mappings(self, text: str) -> Dict[str, Any]:
        """Get CWE mappings from text using LLM"""
        system_prompt = """You are a cybersecurity expert. Analyze the given attack scenario and identify relevant CWE (Common Weakness Enumeration) entries.

For each identified vulnerability, provide:
MITRE_CWE: CWE-<number>
- CWE_Name: <MITRE CWE name>
- vulnerability: <brief summary of the vulnerability>

Focus on actual security weaknesses, not defensive measures."""
        
        prompt = f"Attack Scenario: {text}"
        response = call_llm_api(
            self.client, 
            prompt, 
            system_prompt,
            model=self.model_name,
            max_tokens=self.max_output_tokens
        )
        
        if not response:
            return {}
        
        # Parse the response
        result_dict = {}
        lines = response.split('\n')
        current_cwe = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('MITRE_CWE'):
                current_cwe = str(line.split(':')[1]).strip()
                if current_cwe not in result_dict:
                    result_dict[current_cwe] = {
                        'CWE_Name': '',
                        'vulnerability': []
                    }
            elif line.startswith('- CWE_Name') and current_cwe:
                cwe_name = str(line.split(':')[1]).strip()
                result_dict[current_cwe]['CWE_Name'] = cwe_name
            elif line.startswith('- vulnerability') and current_cwe:
                vulnerability = str(line.split(':')[1]).strip()
                result_dict[current_cwe]['vulnerability'].append(vulnerability)
        
        return result_dict
    
    def get_mitre_mappings(self, text: str) -> Dict[str, Any]:
        """Get MITRE ATT&CK mappings from text using LLM"""
        system_prompt = """You are a cybersecurity expert. Analyze the given attack scenario and identify relevant MITRE ATT&CK techniques.

For each identified technique, provide:
MITRE_TECHNIQUE: T<number>.<subnumber>
- TECHNIQUE_NAME: <MITRE ATT&CK technique name>
- TACTIC: <MITRE ATT&CK tactic>
- ATTACK_BEHAVIOR: <brief summary of the attack behavior>

Focus on actual attack techniques, not defensive measures."""
        
        prompt = f"Attack Scenario: {text}"
        response = call_llm_api(
            self.client, 
            prompt, 
            system_prompt,
            model=self.model_name,
            max_tokens=self.max_output_tokens
        )
        
        if not response:
            return {}
        
        # Parse the response
        result_dict = {}
        lines = response.split('\n')
        current_technique = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('MITRE_TECHNIQUE'):
                current_technique = str(line.split(':')[1]).strip()
                if current_technique not in result_dict:
                    result_dict[current_technique] = {
                        'TECHNIQUE_NAME': '',
                        'TACTIC': '',
                        'ATTACK_BEHAVIOR': []
                    }
            elif line.startswith('- TECHNIQUE_NAME') and current_technique:
                technique_name = str(line.split(':')[1]).strip()
                result_dict[current_technique]['TECHNIQUE_NAME'] = technique_name
            elif line.startswith('- TACTIC') and current_technique:
                tactic = str(line.split(':')[1]).strip()
                result_dict[current_technique]['TACTIC'] = tactic
            elif line.startswith('- ATTACK_BEHAVIOR') and current_technique:
                behavior = str(line.split(':')[1]).strip()
                result_dict[current_technique]['ATTACK_BEHAVIOR'].append(behavior)
        
        return result_dict
    
    def get_capec_mappings(self, text: str) -> Dict[str, Any]:
        """Get CAPEC mappings from text using LLM"""
        system_prompt = """You are a cybersecurity expert. Analyze the given attack scenario and identify relevant CAPEC (Common Attack Pattern Enumeration and Classification) entries.

For each identified attack pattern, provide:
CAPEC_ID: CAPEC-<number>
- CAPEC_Name: <CAPEC attack pattern name>
- attack_pattern: <brief summary of the attack pattern>

Focus on actual attack patterns, not defensive measures. Ensure you provide both the CAPEC_Name and attack_pattern for each CAPEC_ID."""
        
        prompt = f"Attack Scenario: {text}"
        response = call_llm_api(
            self.client, 
            prompt, 
            system_prompt,
            model=self.model_name,
            max_tokens=self.max_output_tokens
        )
        
        if not response:
            return {}
        
        # Parse the response with improved robustness
        result_dict = {}
        lines = response.split('\n')
        current_capec = None
        current_field = None
        
        for line in lines:
            line = line.strip()
            if not line:
                current_field = None
                continue
            
            # Try to match CAPEC_ID in various formats
            if 'CAPEC_ID' in line or 'CAPEC-' in line:
                # Extract CAPEC ID from various formats
                capec_match = re.search(r'CAPEC-?\s*(\d+)', line, re.IGNORECASE)
                if capec_match:
                    current_capec = f"CAPEC-{capec_match.group(1)}"
                    if current_capec not in result_dict:
                        result_dict[current_capec] = {
                            'CAPEC_Name': '',
                            'attack_pattern': []
                        }
                    current_field = None
                    continue
            
            # If we have a current CAPEC entry, try to extract name or pattern
            if current_capec:
                # Try to match CAPEC_Name
                if 'CAPEC_Name' in line or 'CAPEC Name' in line:
                    # Extract name after colon or dash
                    parts = re.split(r'[:\-]', line, 1)
                    if len(parts) > 1:
                        capec_name = parts[1].strip()
                        if capec_name:
                            result_dict[current_capec]['CAPEC_Name'] = capec_name
                    current_field = 'name'
                    continue
                
                # Try to match attack_pattern
                if 'attack_pattern' in line.lower() or 'attack pattern' in line.lower():
                    # Extract pattern after colon or dash
                    parts = re.split(r'[:\-]', line, 1)
                    if len(parts) > 1:
                        pattern = parts[1].strip()
                        if pattern:
                            result_dict[current_capec]['attack_pattern'].append(pattern)
                    current_field = 'pattern'
                    continue
                
                # If we're in a multi-line pattern description, continue collecting
                if current_field == 'pattern' and line and not line.startswith('-') and not 'CAPEC' in line.upper():
                    # This might be a continuation of the attack pattern
                    if result_dict[current_capec]['attack_pattern']:
                        # Append to last pattern if it seems incomplete
                        last_pattern = result_dict[current_capec]['attack_pattern'][-1]
                        if len(last_pattern) < 100:  # If last pattern is short, might be incomplete
                            result_dict[current_capec]['attack_pattern'][-1] = last_pattern + " " + line
                        else:
                            result_dict[current_capec]['attack_pattern'].append(line)
                    continue
                
                # If line starts with dash and we're looking for name or pattern
                if line.startswith('-'):
                    parts = re.split(r'[:\-]', line, 1)
                    if len(parts) > 1:
                        content = parts[1].strip()
                        if content:
                            # Try to determine if it's name or pattern based on content
                            if not result_dict[current_capec]['CAPEC_Name'] and len(content) < 200:
                                # Likely a name if it's short
                                result_dict[current_capec]['CAPEC_Name'] = content
                            else:
                                # Likely a pattern
                                result_dict[current_capec]['attack_pattern'].append(content)
        
        # Filter out entries with empty name and pattern
        filtered_dict = {}
        for capec_id, capec_info in result_dict.items():
            if capec_info.get('CAPEC_Name') or capec_info.get('attack_pattern'):
                filtered_dict[capec_id] = capec_info
        
        return filtered_dict
    
    def get_cve_mappings(self, text: str) -> Dict[str, Any]:
        """Get CVE mappings from text using LLM"""
        system_prompt = """You are a cybersecurity expert. Analyze the given security incident and identify relevant CVE (Common Vulnerabilities and Exposures) entries if they are explicitly mentioned or clearly identifiable.

For each identified CVE, provide:
CVE_ID: CVE-<year>-<number>
- CVE_Description: <brief description of the vulnerability>
- exploit_context: <how the CVE is exploited in this context>

IMPORTANT: Only identify CVEs that are explicitly mentioned or clearly identifiable from the text. Do not speculate or infer CVEs that are not present."""
        
        prompt = f"Security Incident: {text}"
        response = call_llm_api(
            self.client, 
            prompt, 
            system_prompt,
            model=self.model_name,
            max_tokens=self.max_output_tokens
        )
        
        if not response:
            return {}
        
        # Parse the response
        result_dict = {}
        lines = response.split('\n')
        current_cve = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('CVE_ID'):
                current_cve = str(line.split(':')[1]).strip()
                if current_cve not in result_dict:
                    result_dict[current_cve] = {
                        'CVE_Description': '',
                        'exploit_context': []
                    }
            elif line.startswith('- CVE_Description') and current_cve:
                cve_desc = str(line.split(':')[1]).strip()
                result_dict[current_cve]['CVE_Description'] = cve_desc
            elif line.startswith('- exploit_context') and current_cve:
                context = str(line.split(':')[1]).strip()
                result_dict[current_cve]['exploit_context'].append(context)
        
        return result_dict
    
    def process_blog_entry(self, blog_entry: Dict) -> Dict:
        """Process a single blog entry"""
        # Try multiple possible field names for id and title
        # Use explicit None check to handle id=0 case
        blog_id = blog_entry.get("id")
        if blog_id is None:
            blog_id = blog_entry.get("blog_id")
        if blog_id is None:
            blog_id = blog_entry.get("_id")
        
        title = blog_entry.get("title")
        if not title:
            title = blog_entry.get("name", "")
        
        result = {
            "id": blog_id,
            "title": title,
            "publish_date": blog_entry.get("publish_date"),
            "link": blog_entry.get("link"),
            "metadata": blog_entry.get("metadata", {}),
            "processing_status": "success",
            "processing_timestamp": datetime.now().isoformat(),
            "processing_method": f"ai_analysis_{self.model_name}_b2f_{self.framework}",
            "errors": [],
            "token_usage": {}
        }
        
        # Try to get text from various fields
        clean_text = blog_entry.get("clean_text") or blog_entry.get("text") or ""
        if not clean_text:
            result["processing_status"] = "failed"
            result["errors"].append("No text found in blog entry")
            return result
        
        try:
            # Truncate text if needed
            truncated_text = truncate_text(clean_text, self.max_input_tokens)
            token_count = count_tokens(truncated_text)
            
            # Get title from blog_id field if available
            blog_id = blog_entry.get('id') or blog_entry.get('blog_id', 'unknown')
            title = blog_entry.get('title', 'No title')
            # If no title, try to extract from text
            if title == 'No title' and clean_text:
                title = clean_text[:50] + "..."
            print(f"🔍 Processing blog ID {blog_id}: {title[:50]}...")
            
            # Get mappings based on framework
            if self.framework == "mitre":
                mappings = self.get_mitre_mappings(truncated_text)
                if mappings:
                    result["mitre_attack"] = {
                        "AttackAnalysis": "AI-analyzed attack scenario from blog content",
                        "ProcessingTime": datetime.now().strftime("%Y_%m_%d_%H_%M_%S"),
                        "TokenCount": token_count,
                        "TechniqueMappings": mappings
                    }
                    result["token_usage"]["mitre_attack"] = token_count
                    print(f"✅ Found {len(mappings)} MITRE technique mappings")
                else:
                    result["errors"].append("Failed to extract MITRE ATT&CK information")
            elif self.framework == "capec":
                mappings = self.get_capec_mappings(truncated_text)
                if mappings:
                    result["capec"] = {
                        "AttackPatternAnalysis": "AI-analyzed attack pattern from blog content",
                        "ProcessingTime": datetime.now().strftime("%Y_%m_%d_%H_%M_%S"),
                        "TokenCount": token_count,
                        "CAPECMappings": mappings
                    }
                    result["token_usage"]["capec"] = token_count
                    print(f"✅ Found {len(mappings)} CAPEC mappings")
                else:
                    result["errors"].append("Failed to extract CAPEC information")
            elif self.framework == "cve":
                mappings = self.get_cve_mappings(truncated_text)
                if mappings:
                    result["cve"] = {
                        "VulnerabilityExploitAnalysis": "AI-analyzed CVE identification from blog content",
                        "ProcessingTime": datetime.now().strftime("%Y_%m_%d_%H_%M_%S"),
                        "TokenCount": token_count,
                        "CVEMappings": mappings
                    }
                    result["token_usage"]["cve"] = token_count
                    print(f"✅ Found {len(mappings)} CVE mappings")
                else:
                    result["errors"].append("Failed to extract CVE information")
            else:  # cwe
                mappings = self.get_cwe_mappings(truncated_text)
                if mappings:
                    result["mitre_cwe"] = {
                        "VulnerabilityAnalysis": "AI-analyzed vulnerability assessment from blog content",
                        "ProcessingTime": datetime.now().strftime("%Y_%m_%d_%H_%M_%S"),
                        "TokenCount": token_count,
                        "CWEMappings": mappings
                    }
                    result["token_usage"]["mitre_cwe"] = token_count
                    print(f"✅ Found {len(mappings)} CWE mappings")
                else:
                    result["errors"].append("Failed to extract CWE information")
                
        except Exception as e:
            result["processing_status"] = "failed"
            result["errors"].append(f"Unexpected processing error: {str(e)}")
        
        return result
    
    def filter_cwe_data(self, data: Dict) -> Dict:
        """Filter CWE data to keep only essential information"""
        blog_info = {
            "blog_id": data.get("id"),
            "title": data.get("title"),
            "cwe_entries": []
        }
        
        mitre_cwe = data.get("mitre_cwe", {})
        cwe_mappings = mitre_cwe.get("CWEMappings", {})
        
        for cwe_id, cwe_info in cwe_mappings.items():
            cwe_entry = {
                "cwe_id": cwe_id,
                "cwe_name": cwe_info.get("CWE_Name", ""),
                "vulnerabilities": cwe_info.get("vulnerability", [])
            }
            blog_info["cwe_entries"].append(cwe_entry)
        
        return blog_info
    
    def filter_mitre_data(self, data: Dict) -> Dict:
        """Filter MITRE data to keep only essential information"""
        blog_info = {
            "blog_id": data.get("id"),
            "title": data.get("title"),
            "technique_entries": []
        }
        
        mitre_attack = data.get("mitre_attack", {})
        technique_mappings = mitre_attack.get("TechniqueMappings", {})
        
        for technique_id, technique_info in technique_mappings.items():
            technique_entry = {
                "technique_id": technique_id,
                "technique_name": technique_info.get("TECHNIQUE_NAME", ""),
                "tactic": technique_info.get("TACTIC", ""),
                "attack_behaviors": technique_info.get("ATTACK_BEHAVIOR", [])
            }
            blog_info["technique_entries"].append(technique_entry)
        
        return blog_info
    
    def filter_capec_data(self, data: Dict) -> Dict:
        """Filter CAPEC data to keep only essential information"""
        # Try multiple possible field names for id and title
        # Use explicit None check to handle id=0 case
        blog_id = data.get("id")
        if blog_id is None:
            blog_id = data.get("blog_id")
        if blog_id is None:
            blog_id = data.get("_id")
        
        title = data.get("title")
        if not title:
            title = data.get("name", "")
        
        blog_info = {
            "blog_id": blog_id,
            "title": title,
            "capec_entries": []
        }
        
        capec_data = data.get("capec", {})
        capec_mappings = capec_data.get("CAPECMappings", {})
        
        for capec_id, capec_info in capec_mappings.items():
            capec_name = capec_info.get("CAPEC_Name", "").strip()
            attack_patterns = capec_info.get("attack_pattern", [])
            # Filter out empty patterns
            attack_patterns = [p.strip() for p in attack_patterns if p and p.strip()]
            
            # Only include entries that have at least a name or patterns
            if capec_name or attack_patterns:
                capec_entry = {
                    "capec_id": capec_id,
                    "capec_name": capec_name,
                    "attack_patterns": attack_patterns
                }
                blog_info["capec_entries"].append(capec_entry)
        
        return blog_info
    
    def filter_cve_data(self, data: Dict) -> Dict:
        """Filter CVE data to keep only essential information"""
        blog_info = {
            "blog_id": data.get("id"),
            "title": data.get("title"),
            "cve_entries": []
        }
        
        cve_data = data.get("cve", {})
        cve_mappings = cve_data.get("CVEMappings", {})
        
        for cve_id, cve_info in cve_mappings.items():
            cve_entry = {
                "cve_id": cve_id,
                "cve_description": cve_info.get("CVE_Description", ""),
                "exploit_contexts": cve_info.get("exploit_context", [])
            }
            blog_info["cve_entries"].append(cve_entry)
        
        return blog_info
    
    def process_all_blogs(self, limit: Optional[int] = None, skip_existing: bool = True) -> bool:
        """Process all blog entries with AI analysis"""
        print(f"🚀 Starting B2F Blog Digger with {self.model_name} for {self.framework.upper()} framework...")
        print(f"📊 Token allocation: {self.max_input_tokens:,} input, {self.max_output_tokens:,} output")
        
        # Load existing blog IDs if skip_existing is enabled
        existing_ids = set()
        if skip_existing and file_exists(str(self.output_file)):
            try:
                existing_blogs = load_jsonl(str(self.output_file))
                for existing_blog in existing_blogs:
                    blog_id = existing_blog.get("id")
                    if blog_id is not None:
                        existing_ids.add(blog_id)
                if existing_ids:
                    print(f"📋 Found {len(existing_ids)} already processed blog IDs: {sorted(existing_ids)}")
            except Exception as e:
                print(f"⚠️  Warning: Could not load existing blog IDs: {e}")
        
        # Load blog data
        blogs = load_jsonl(str(self.input_file))
        if not blogs:
            print("❌ No blog data to process")
            return False
        
        # Apply limit if specified
        if limit:
            blogs = blogs[:limit]
            print(f"📝 Processing limited to {len(blogs)} blogs")
        
        # Filter out already processed blogs
        blogs_to_process = []
        skipped_count = 0
        for blog in blogs:
            blog_id = blog.get("id")
            if blog_id is None:
                blog_id = blog.get("blog_id")
            if blog_id is None:
                blog_id = blog.get("_id")
            
            if skip_existing and blog_id in existing_ids:
                skipped_count += 1
                continue
            
            blogs_to_process.append(blog)
        
        if skipped_count > 0:
            print(f"⏭️  Skipping {skipped_count} already processed blog(s)")
        
        print(f"🔍 Processing {len(blogs_to_process)} blog entries...")
        
        if len(blogs_to_process) == 0:
            print("✅ All blogs have already been processed!")
            return True
        
        # Process each blog entry
        results = []
        filtered_results = []
        total_tokens_used = 0
        
        for i, blog in enumerate(blogs_to_process, 1):
            print(f"\n📝 Processing blog {i}/{len(blogs_to_process)}: {blog.get('title', 'No title')[:50]}...")
            
            try:
                result = self.process_blog_entry(blog)
                results.append(result)
                
                # Save result immediately
                if self.save_single_result(result):
                    print(f"✅ Saved result for blog ID {result.get('id', 'unknown')}")
                
                # Update token usage
                if self.framework == "mitre":
                    total_tokens_used += result.get("token_usage", {}).get("mitre_attack", 0)
                elif self.framework == "capec":
                    total_tokens_used += result.get("token_usage", {}).get("capec", 0)
                elif self.framework == "cve":
                    total_tokens_used += result.get("token_usage", {}).get("cve", 0)
                else:
                    total_tokens_used += result.get("token_usage", {}).get("mitre_cwe", 0)
                
                # Create filtered version if successful
                if result["processing_status"] == "success":
                    if self.framework == "mitre" and result.get("mitre_attack"):
                        filtered_data = self.filter_mitre_data(result)
                        if filtered_data["technique_entries"]:
                            filtered_results.append(filtered_data)
                    elif self.framework == "capec" and result.get("capec"):
                        filtered_data = self.filter_capec_data(result)
                        if filtered_data["capec_entries"]:
                            filtered_results.append(filtered_data)
                    elif self.framework == "cve" and result.get("cve"):
                        filtered_data = self.filter_cve_data(result)
                        if filtered_data["cve_entries"]:
                            filtered_results.append(filtered_data)
                    elif self.framework == "cwe" and result.get("mitre_cwe"):
                        filtered_data = self.filter_cwe_data(result)
                        if filtered_data["cwe_entries"]:
                            filtered_results.append(filtered_data)
                
            except Exception as e:
                print(f"❌ Error processing blog {i}: {e}")
        
        # Print summary
        successful = sum(1 for r in results if r["processing_status"] == "success")
        failed = sum(1 for r in results if r["processing_status"] == "failed")
        
        print(f"\n📊 B2F Blog Digger Summary ({self.framework.upper()})")
        print(f"Total entries: {len(results)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Total tokens used: {total_tokens_used:,}")
        print(f"Filtered entries: {len(filtered_results)}")
        
        return successful > 0
    
    def save_single_result(self, result: Dict) -> bool:
        """Save a single processed result"""
        try:
            # Save full result
            with open(self.output_file, 'a', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False)
                f.write('\n')
            
            # Save filtered result if available
            if self.framework == "mitre" and result.get("mitre_attack"):
                filtered_data = self.filter_mitre_data(result)
                if filtered_data["technique_entries"]:
                    with open(self.filtered_output_file, 'a', encoding='utf-8') as f:
                        json.dump(filtered_data, f, ensure_ascii=False)
                        f.write('\n')
            elif self.framework == "capec" and result.get("capec"):
                filtered_data = self.filter_capec_data(result)
                if filtered_data["capec_entries"]:
                    with open(self.filtered_output_file, 'a', encoding='utf-8') as f:
                        json.dump(filtered_data, f, ensure_ascii=False)
                        f.write('\n')
            elif self.framework == "cve" and result.get("cve"):
                filtered_data = self.filter_cve_data(result)
                if filtered_data["cve_entries"]:
                    with open(self.filtered_output_file, 'a', encoding='utf-8') as f:
                        json.dump(filtered_data, f, ensure_ascii=False)
                        f.write('\n')
            elif self.framework == "cwe" and result.get("mitre_cwe"):
                filtered_data = self.filter_cwe_data(result)
                if filtered_data["cwe_entries"]:
                    with open(self.filtered_output_file, 'a', encoding='utf-8') as f:
                        json.dump(filtered_data, f, ensure_ascii=False)
                        f.write('\n')
            
            return True
        except Exception as e:
            print(f"❌ Error saving result: {e}")
            return False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="B2F Blog Digger - AI-powered CWE/MITRE/CAPEC/CVE extraction")
    parser.add_argument("--limit", type=int, help="Number of blogs to process")
    parser.add_argument("--model", type=str, default=LLM_MODEL, help="LLM model to use")
    parser.add_argument("--framework", type=str, default="cwe", choices=["cwe", "mitre", "capec", "cve"], 
                       help="Framework to use: cwe, mitre, capec, or cve (default: cwe)")
    
    args = parser.parse_args()
    
    try:
        digger = BlogDigger(model_name=args.model, framework=args.framework)
        success = digger.process_all_blogs(limit=args.limit)
        
        if success:
            print(f"\n🎉 B2F Blog Digger completed successfully for {args.framework.upper()}!")
        else:
            print(f"\n❌ B2F Blog Digger encountered errors")
            
    except Exception as e:
        print(f"❌ Failed to initialize B2F Blog Digger: {e}")

if __name__ == "__main__":
    main()
