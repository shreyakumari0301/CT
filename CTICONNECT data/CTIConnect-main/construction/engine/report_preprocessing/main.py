#!/usr/bin/env python3
"""
Report Preprocessing Pipeline.

Compresses long-form vendor threat reports into entity-preserving executive
summaries that downstream retrieval consumes (the ``preprocessed`` field of
``corpus_reports/preprocessed_reports.jsonl``). See ``README.md`` for the design
contract that constrains the summarisation prompt.

Usage:
    python main.py [--test]

Arguments:
    --test: Run in test mode (process only first 3 entries)

Configuration:
    - Model: ``gpt-4o`` (override via ``LLM_MODEL`` below)
    - Requires ``OPENAI_API_KEY`` in a ``.env`` file in this directory
"""

import json
import os
import sys
import time
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
import openai
from dotenv import load_dotenv

# Add parent directories to path for imports
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
sys.path.append(str(root_dir))

# Load environment variables from this module's directory
load_dotenv(current_dir / ".env")

# Configuration
ROOT_DIR = Path(__file__).parent.parent.parent.parent
# Raw long-form vendor reports (not redistributed for copyright reasons).
INPUT_FILE = ROOT_DIR / "corpus_reports/blog_raw.jsonl"
# Entity-preserving preprocessed reports --- the shipped retrieval corpus.
OUTPUT_FILE = ROOT_DIR / "corpus_reports/preprocessed_reports.jsonl"
LLM_MODEL = "gpt-4o"
MAX_TOKENS = 4000
MAX_RETRIES = 3

class ReportPreprocessor:
    """Generate entity-preserving preprocessed outputs from raw vendor reports.

    The output is the ``preprocessed`` field of ``preprocessed_reports.jsonl`` --- the
    downstream retrieval corpus. The summarisation prompt enforces an
    entity-preservation contract (see ``_build_preprocessing_prompt``) so that
    NER and embedding-based retrieval do not lose CTI signal.
    """
    
    def __init__(self, test_mode: bool = False):
        """Initialize the generator with OpenAI client"""
        self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.processed_ids = set()
        self.test_mode = test_mode
        self._load_processed_ids()
    
    def _load_processed_ids(self):
        """Load IDs of already-processed records to support resumption."""
        if OUTPUT_FILE.exists():
            try:
                with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            entry = json.loads(line)
                            self.processed_ids.add(entry['id'])
                print(f"✅ Loaded {len(self.processed_ids)} already-processed records")
            except Exception as e:
                print(f"⚠️  Warning: Could not load existing records: {e}")
    
    def call_llm_api(self, prompt: str, system_prompt: str = None, 
                     max_tokens: int = MAX_TOKENS) -> Optional[str]:
        """Make a call to LLM API with retry logic"""
        
        for attempt in range(MAX_RETRIES):
            try:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                
                # Use max_completion_tokens for o4-mini
                response = self.client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=messages,
                    max_completion_tokens=max_tokens
                )
                
                return response.choices[0].message.content.strip()
                
            except Exception as e:
                print(f"⚠️  LLM API call failed (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"❌ All retry attempts failed")
                    return None
        
        return None
    
    def _build_preprocessing_prompt(self, blog_entry: Dict[str, Any]) -> str:
        """Build the entity-preserving summarisation prompt.

        Design contract: the summary feeds (i) STIX-aligned NER for the
        CSKG-Guided RAG baseline and (ii) dense embedding for vanilla RAG.
        Both pipelines never see the raw report again, so every CTI entity
        mention in the source must survive verbatim into the summary. The
        STIX entity types enumerated below mirror
        ``baselines/ctinexus_lite/ontology.py:ENTITY_TYPES`` --- keep the
        two in sync if either side changes.
        """
        title = blog_entry.get('title', 'Unknown Title')
        clean_text = blog_entry.get('clean_text', '')

        # Truncate over-long bodies. NOTE: hard truncation can drop
        # entities mentioned only near the report tail. For full coverage
        # of >12K-char reports, switch to chunked summarisation; the
        # current corpus rarely hits this bound.
        max_text_length = 12000
        if len(clean_text) > max_text_length:
            clean_text = clean_text[:max_text_length] + "..."

        prompt = f"""Condense the following cyber threat intelligence (CTI) report into a single dense paragraph. The output will be consumed by automated NER and embedding-based retrieval, so the summary MUST preserve every CTI entity from the source verbatim; you may freely cut narrative noise.

Title: {title}

Content:
{clean_text}

## Preserve verbatim (STIX-aligned, include EVERY mention from the source)
1. threat_actor   -- group / operator names AND all aliases used in the report (e.g., "APT29", "Cozy Bear", "Nobelium", "Midnight Blizzard", "UNC2452"). Never collapse an alias cluster into a generic descriptor such as "a Russian state-sponsored group".
2. campaign       -- named operations / campaigns (e.g., "Operation Aurora", "EleKtra-Leak").
3. malware        -- malware family / instance names AND variant suffixes (e.g., "LockBit 3.0", "QakBot", "Cobalt Strike Beacon").
4. tool           -- dual-use / legitimate tools repurposed offensively (e.g., "PsExec", "Mimikatz", "AnyDesk").
5. attack_pattern -- MITRE ATT&CK technique IDs and sub-techniques (e.g., "T1059.001", "T1566.001") and any technique names used.
6. vulnerability  -- every CVE ID exactly as written (e.g., "CVE-2024-3400"), plus affected product/version where given.
7. weakness       -- every CWE ID (e.g., "CWE-79", "CWE-787") and CAPEC ID (e.g., "CAPEC-66") that appears.
8. indicator      -- IoCs: IPs (defanged form OK), domains, URLs, file hashes (MD5/SHA1/SHA256), file paths, registry keys, email addresses. List them inline, never paraphrase to "attacker infrastructure".
9. identity       -- named victim organisations, named target sectors (e.g., "U.S. Department of Defense", "European energy sector", "Ukrainian government"). Do not generalise specific named victims.

## You MAY condense or remove
- Vendor self-promotion, marketing copy, calls-to-action.
- Generic background paragraphs (history of ransomware, definitions of common terms, etc.).
- Redundant repetition of the same fact across the report.
- Legal disclaimers, copyright notices, "about the author" boilerplate.
- Reference / source-link blocks at the end of the post.

## Output format
- One single paragraph (no headings, no bullets, no markdown).
- Keep the chronological / causal flow of the original where it carries CTI signal (e.g., initial access -> lateral movement -> impact).
- It is acceptable for the paragraph to be LONG; brevity matters less than entity preservation.
- Return only the paragraph -- no preamble, no closing remark, no code fences.
"""

        return prompt

    def preprocess_report(self, blog_entry: Dict[str, Any]) -> Optional[str]:
        """Run the entity-preserving preprocessing pipeline on a single report."""

        system_prompt = (
            "You are a Cyber Threat Intelligence (CTI) analyst producing "
            "entity-preserving preprocessed outputs. Your output is fed "
            "verbatim into (a) STIX-aligned named-entity extraction and "
            "(b) dense embedding for cross-report retrieval. Dropping any "
            "named CTI entity (threat actor / alias, campaign, malware, "
            "tool, ATT&CK technique, CVE, CWE, CAPEC, IOC, named victim) "
            "destroys downstream retrieval signal and is unacceptable. "
            "Cut narrative noise, not entities."
        )
        
        prompt = self._build_preprocessing_prompt(blog_entry)

        return self.call_llm_api(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=MAX_TOKENS,
        )

    def process_blog_entry(self, blog_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single report entry and produce its preprocessed output."""

        blog_id = blog_entry.get('id')
        if blog_id in self.processed_ids:
            print(f"⏭️  Skipping already processed entry {blog_id}")
            return None

        print(f"🔄 Processing report {blog_id}: {blog_entry.get('title', 'Unknown')}")

        try:
            preprocessed = self.preprocess_report(blog_entry)

            if not preprocessed:
                print(f"❌ Failed to preprocess report {blog_id}")
                return None

            output_entry = {
                "id": blog_entry.get('id'),
                "title": blog_entry.get('title'),
                "publish_date": blog_entry.get('publish_date'),
                "link": blog_entry.get('link'),
                "preprocessed": preprocessed,
                "metadata": blog_entry.get('metadata', {}),
            }

            print(f"✅ Preprocessed report {blog_id}")
            return output_entry
            
        except Exception as e:
            print(f"❌ Error processing entry {blog_id}: {e}")
            return None
    
    def process_all_entries(self):
        """Process all reports and write entity-preserving preprocessed output"""
        
        if not INPUT_FILE.exists():
            print(f"❌ Input file not found: {INPUT_FILE}")
            return
        
        # Count total entries
        total_entries = 0
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    total_entries += 1
        
        if self.test_mode:
            total_entries = min(total_entries, 3)
            print(f"🧪 Test mode: processing only first {total_entries} entries")
        
        print(f"📊 Total entries to process: {total_entries}")
        print(f"📊 Already processed: {len(self.processed_ids)}")
        print(f"📊 Remaining: {total_entries - len(self.processed_ids)}")
        
        processed_count = 0
        skipped_count = len(self.processed_ids)
        
        # Open output file in append mode
        with open(OUTPUT_FILE, 'a', encoding='utf-8') as output_file:
            with open(INPUT_FILE, 'r', encoding='utf-8') as input_file:
                for line_num, line in enumerate(input_file, 1):
                    if not line.strip():
                        continue
                    
                    # Stop if test mode and we've processed enough
                    if self.test_mode and (processed_count + skipped_count) >= 3:
                        break
                    
                    try:
                        blog_entry = json.loads(line)
                        
                        # Process the entry
                        result = self.process_blog_entry(blog_entry)
                        
                        if result:
                            # Write to output file
                            output_file.write(json.dumps(result, ensure_ascii=False) + '\n')
                            output_file.flush()  # Ensure data is written immediately
                            processed_count += 1
                            self.processed_ids.add(result['id'])
                        else:
                            skipped_count += 1
                        
                        # Progress update
                        if (processed_count + skipped_count) % 10 == 0:
                            print(f"📈 Progress: {processed_count + skipped_count}/{total_entries} "
                                  f"(Processed: {processed_count}, Skipped: {skipped_count})")
                    
                    except json.JSONDecodeError as e:
                        print(f"⚠️  Invalid JSON on line {line_num}: {e}")
                        continue
                    except Exception as e:
                        print(f"❌ Unexpected error on line {line_num}: {e}")
                        continue
        
        print(f"\n🎉 Processing complete!")
        print(f"📊 Total processed: {processed_count}")
        print(f"📊 Total skipped: {skipped_count}")
        print(f"📄 Output written to: {OUTPUT_FILE}")

def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run the entity-preserving report preprocessing pipeline")
    parser.add_argument("--test", action="store_true", help="Run in test mode (process only first 3 entries)")
    args = parser.parse_args()
    
    print("🚀 Starting Report Preprocessing Pipeline...")

    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key in .env file or environment variables")
        print("Please create a .env file in this directory with your OpenAI API key")
        return

    # Initialize generator
    generator = ReportPreprocessor(test_mode=args.test)
    
    # Process all entries
    generator.process_all_entries()
    
    print("✨ Done!")

if __name__ == "__main__":
    main()
