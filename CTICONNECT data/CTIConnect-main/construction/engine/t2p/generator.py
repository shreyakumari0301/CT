#!/usr/bin/env python3
"""
Template to Prompt (t2p) Generator

This module generates prompts by combining entries with correlation data
using the predefined Jinja2 templates. Supports batching with random sampling.
"""

import json
import re
import sys
import random
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

from jinja2 import Environment, FileSystemLoader, Template


class PromptGenerator:
    """Generator for relationship prompts using Jinja2 templates."""
    
    def __init__(self,
                 corpus_dir: str,
                 correlation_dir: str,
                 output_dir: str,
                 template_dir: str,
                 task: str,
                 template_version: str,
                 enable_batching: bool = False,
                 batch_size: int = 100,
                 restart: bool = False,
                 blog_cluster_file: str = None):
        """
        Initialize the prompt generator.

        Args:
            corpus_dir: Path to corpus entries JSONL files
            correlation_dir: Path to correlation data JSONL files
            template_dir: Path to Jinja2 template files
            output_dir: Directory to save generated prompts
            task: Task identifier (rcm, cca, csc, eea, etc.)
            template_version: Template version (v1, v2, v5, etc.)
            enable_batching: Whether to create batches after generation
            batch_size: Number of prompts per batch (default: 100)
            restart: Whether to remove existing files in output directory (default: False)
            blog_cluster_file: Path to BlogCluster.csv file for CSC/TAP/MLA tasks (default: datasets/BlogCluster.csv)
        """
        self.task = task
        self.template_version = template_version
        self.enable_batching = enable_batching
        self.batch_size = batch_size
        self.restart = restart
        
        self.corpus_dir = Path(corpus_dir)
        self.correlation_dir = Path(correlation_dir)
        self.template_dir = Path(template_dir)
        
        # Set blog cluster file path
        if blog_cluster_file:
            self.blog_cluster_file = Path(blog_cluster_file)
        else:
            # Default path for BlogCluster.csv
            self.blog_cluster_file = Path("datasets/BlogCluster.csv")
        
        # Path structure: prompts/{task}/{template-version}/
        self.output_dir = Path(output_dir) / task / template_version
        
        # Data storage
        self.source_entries: Dict[str, Dict[str, Any]] = {}
        self.target_entries: Dict[str, Dict[str, Any]] = {}
        self.correlation_data: List[Dict[str, Any]] = []
        
        # Jinja2 template
        self.template: Optional[Template] = None
        
    def _extract_mitre_id_from_technique(self, technique_field: str) -> str:
        """Extract MITRE ATT&CK technique ID (e.g., T1204.002) from a technique string.

        The input may look like:
            "technique: T1204.002 - User Execution: Malicious File"
            or simply "T1498 - Network Denial of Service".

        Returns the best-effort extracted ID, or a sanitized fallback.
        """
        if not technique_field:
            return "TUNKNOWN"
        text = str(technique_field).strip()
        # Common prefix like "technique:" → drop
        if text.lower().startswith("technique:"):
            text = text.split(":", 1)[1].strip()
        # Find first token starting with T
        first_token = text.split()[0]
        token_upper = first_token.upper()
        return token_upper if token_upper.startswith("T") else f"T{token_upper}"

    def generate_prompts_for_vca(self) -> None:
        """Special-case generator for VCA task using seeds/correlations/b2f_cwe.jsonl.

        For each entry in b2f_cwe.jsonl:
          - vulnerability_text field as SOURCE_NODE passed to the template
          - cwe_id used to find corresponding CWE entry from corpus_kb/cwe.jsonl as TARGET_NODE
        """
        if not self.template:
            raise RuntimeError("Template not loaded. Call load_template() first.")

        # Load CWE data for target nodes
        print("Loading CWE data for target nodes...")
        cwe_entries = self.load_corpus_data("cwe")

        total_pairs = 0
        generated_pairs = 0
        saved_pairs = 0

        print("Generating VCA prompts from seeds/correlations/b2f_cwe.jsonl...")

        for entry in self.correlation_data:
            cwe_id = entry.get("cwe_id", "")
            blog_id = entry.get("blog_id", "")
            blog_title = entry.get("blog_title", "")
            vulnerability_text = entry.get("vulnerability_text", "")

            if not vulnerability_text:
                continue

            # Format CWE ID for filename and lookup
            display_target_id = self.format_identifier("cwe", cwe_id)
            
            # Display-friendly source id for filenames
            display_source_id = f"blog-{blog_id}" if blog_id is not None else "blog-unknown"

            # Find corresponding CWE entry
            # Remove CWE- prefix for lookup since corpus uses numeric IDs
            cwe_lookup_id = cwe_id.replace("CWE-", "") if cwe_id.startswith("CWE-") else cwe_id
            target_entry = cwe_entries.get(cwe_lookup_id)
            if not target_entry:
                print(f"Warning: CWE entry {cwe_id} (lookup: {cwe_lookup_id}) not found for {display_source_id}", file=sys.stderr)
                continue

            total_pairs += 1

            try:
                # Pass only the vulnerability_text field as SOURCE_NODE
                # Remove 'id' from target entry to avoid conflicts
                clean_target_entry = self.get_target_entry_without_id(target_entry)
                
                prompt = self.template.render(
                    SOURCE_NODE=vulnerability_text,
                    TARGET_NODE=json.dumps(clean_target_entry, indent=2)
                )
            except Exception as e:
                print(f"Error rendering VCA template for {display_source_id}-{display_target_id}: {e}", file=sys.stderr)
                continue

            if prompt:
                generated_pairs += 1
                if self.save_prompt(prompt, display_source_id, display_target_id):
                    saved_pairs += 1
                    if saved_pairs % 50 == 0:
                        print(f"Progress: {saved_pairs}/{total_pairs} VCA prompts saved")

        print(f"\nVCA generation complete:")
        print(f"  Total entries: {total_pairs}")
        print(f"  Successfully generated: {generated_pairs}")
        print(f"  Successfully saved: {saved_pairs}")
        print(f"  Output directory: {self.output_dir}")

    def format_identifier(self, task: str, source_id: str, target_id: str) -> tuple:
        """Format identifiers with canonical prefixes for filenames.

        - cve  -> CVE-<id>
        - cwe  -> CWE-<id>
        - capec-> CAPEC-<id>
        - mitre-> T<id> (preserve sub-technique suffix like .001)
        - blog -> return raw_id (blogs are special-cased elsewhere)
        """
        if target_id is None:
            return None, None
        tid = str(target_id)
        t = (task or "").lower()
        if t == "vca":
            sid = str(source_id) if source_id else ""
            formatted_sid = sid if sid.upper().startswith("BLOG-") else f"BLOG-{sid}"
            formatted_tid = tid if tid.upper().startswith("CWE-") else f"CWE-{tid}"
            return formatted_sid, formatted_tid
        if t == "ata":
            sid = str(source_id) if source_id else ""
            formatted_sid = sid if sid.upper().startswith("BLOG-") else f"BLOG-{sid}"
            formatted_tid = tid if tid.upper().startswith("T") else f"T{tid}"
            return formatted_sid, formatted_tid
        return None, None

    def load_corpus_data(self, corpus_type: str) -> Dict[str, Dict[str, Any]]:
        """Load corpus entries from JSONL file into memory."""
        corpus_data_path = self.corpus_dir / f"{corpus_type}.jsonl"
        print(f"Loading {corpus_type} data from {corpus_data_path}...")
        
        if not corpus_data_path.exists():
            raise FileNotFoundError(f"{corpus_type} data file not found: {corpus_data_path}")
        
        entries = {}
        count = 0
        
        with open(corpus_data_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    entry = json.loads(line)
                    
                    # Handle blog entries differently (use 'id' field instead of 'blog_id')
                    if corpus_type == "blog":
                        corpus_id = entry.get('id')
                    else:
                        corpus_id = entry.get(f'{corpus_type}_id')
                    
                    if corpus_id is not None:  # Allow 0 as valid ID
                        # Convert to string for consistent lookup
                        corpus_id = str(corpus_id)
                        entries[corpus_id] = entry
                        count += 1
                        
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error at line {line_num}: {e}", file=sys.stderr)
                    continue
        
        print(f"Loaded {count} {corpus_type} entries")
        return entries

    def load_original_cwe_data(self) -> Dict[str, Dict[str, Any]]:
        """Load original CWE data from corpus_kb/cwe.jsonl (not filtered)."""
        original_cwe_path = Path("corpus_kb") / "cwe.jsonl"
        print(f"Loading original CWE data from {original_cwe_path}...")
        
        if not original_cwe_path.exists():
            raise FileNotFoundError(f"Original CWE data file not found: {original_cwe_path}")
        
        entries = {}
        count = 0
        with open(original_cwe_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    entry = json.loads(line)
                    key = entry.get("cwe_id")
                    
                    if key is not None:
                        entries[str(key)] = entry
                        count += 1
                        
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error at line {line_num}: {e}", file=sys.stderr)
                    continue
        
        print(f"Loaded {count} original CWE entries")
        return entries

    def load_preprocessed_reports_corpus(self) -> Dict[str, Dict[str, Any]]:
        """
        Load report records from preprocessed_reports.jsonl keyed by blog id.

        Expected fields per line include at least: id, publish_date, preprocessed.
        """
        # If corpus_dir is already a file path, use it directly
        if self.corpus_dir.suffix == '.jsonl':
            preprocessed_path = self.corpus_dir
        else:
            # If corpus_dir is a directory, append the filename
            preprocessed_path = self.corpus_dir / "preprocessed_reports.jsonl"
        
        print(f"Loading preprocessed reports from {preprocessed_path}...")

        if not preprocessed_path.exists():
            raise FileNotFoundError(f"preprocessed_reports.jsonl file not found: {preprocessed_path}")

        entries: Dict[str, Dict[str, Any]] = {}
        count = 0
        with open(preprocessed_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    corpus_id = entry.get('id')
                    if corpus_id is not None:
                        entries[str(corpus_id)] = entry
                        count += 1
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error at line {line_num}: {e}", file=sys.stderr)
                    continue

        print(f"Loaded {count} preprocessed report entries")
        return entries
    
    def load_correlation_data(self, task: str) -> None:
        """Load correlation data from JSONL file with filtering for specific tasks."""
        if task == "vca":
            correlation_file = self.correlation_dir / "b2f_cwe.jsonl"
        elif task == "ata":
            correlation_file = self.correlation_dir / "b2f_mitre.jsonl"
        elif task == "rcm":
            correlation_file = self.correlation_dir / "cve_xrefs.jsonl"
        elif task == "wim":
            correlation_file = self.correlation_dir / "cwe_xrefs.jsonl"
        elif task == "atd":
            correlation_file = self.correlation_dir / "capec_xrefs.jsonl"
        elif task == "esd":
            correlation_file = self.correlation_dir / "cwe_xrefs.jsonl"
        elif task in ["csc", "tap", "mla"]:
            # For CSC/TAP/MLA tasks, we use BlogCluster.csv instead of JSONL
            return self.load_blog_cluster_data()
        else:
            # Default case - try to load a generic correlation file
            correlation_file = self.correlation_dir / f"{task}.jsonl"
        
        print(f"Loading correlation data from {correlation_file}...")
        
        if not correlation_file.exists():
            raise FileNotFoundError(f"Correlation data file not found: {correlation_file}")
        
        count = 0
        filtered_count = 0
        
        with open(correlation_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
        
                try:
                    entry = json.loads(line)
                    
                    # Apply filtering for specific tasks
                    if self._should_include_entry(entry, task):
                        self.correlation_data.append(entry)
                        filtered_count += 1
                    
                    count += 1
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error at line {line_num}: {e}", file=sys.stderr)
                    continue
        
        print(f"Loaded {count} total entries from {correlation_file}")
        print(f"Filtered to {filtered_count} entries with required relationships for {task.upper()} task")

    def _should_include_entry(self, entry: Dict[str, Any], task: str) -> bool:
        """
        Determine if an entry should be included based on task-specific filtering criteria.
        For RCM/WIM/ATD/ESD tasks, only include entries with single (one-to-one) relationships.
        
        Args:
            entry: The correlation data entry to check
            task: The task identifier (rcm, wim, atd, esd)
            
        Returns:
            True if the entry should be included, False otherwise
        """
        if task == "rcm":
            # RCM: Only include CVE entries that have exactly one correlated_cwe
            correlated_cwe = entry.get("correlated_cwe")
            return correlated_cwe is not None and len(correlated_cwe) == 1
            
        elif task == "wim":
            # WIM: Include CWE entries that have at least one correlated_cve.
            # The downstream iteration emits one prompt per (CWE, CVE) pair.
            # `== 1` was too strict (yielded only 71 prompts vs. the 100 required
            # by paper Tab. tab:expansion_per_task); relaxing to `>= 1` exposes
            # ~2998 candidate pairs across 550 CWEs.
            correlated_cve = entry.get("correlated_cve")
            return correlated_cve is not None and len(correlated_cve) >= 1
            
        elif task == "atd":
            # ATD: Only include CAPEC entries that have exactly one correlated_mitre
            correlated_mitre = entry.get("correlated_mitre")
            return correlated_mitre is not None and len(correlated_mitre) == 1
            
        elif task == "esd":
            # ESD: Only include CWE entries that have exactly one correlated_capec
            correlated_capec = entry.get("correlated_capec")
            return correlated_capec is not None and len(correlated_capec) == 1
            
        else:
            # For other tasks (vca, ata, csc, tap, mla), include all entries
            return True

    def load_blog_cluster_data(self) -> None:
        """Load BlogCluster.csv data for CSC/TAP/MLA tasks."""
        import csv
        
        print(f"Loading BlogCluster data from {self.blog_cluster_file}...")
        
        if not self.blog_cluster_file.exists():
            raise FileNotFoundError(f"BlogCluster.csv file not found: {self.blog_cluster_file}")
        
        count = 0
        with open(self.blog_cluster_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, 1):
                try:
                    # Skip rows with empty object_id
                    if not row.get("object_id", "").strip():
                        print(f"Warning: Skipping row {row_num} - empty object_id")
                        continue
                    
                    # Convert to the expected format - handle potential whitespace in column names
                    entry = {
                        "object_id": int(row["object_id"]),
                        "title": row.get(" Title", row.get("title", "")).strip(),  # Handle space before Title
                        "platform": row.get("platform", ""),
                        "link": row.get("link", ""),
                        "type": row.get("type", ""),
                        "blog_id": int(row["blog_id"]) if row.get("blog_id", "").strip() else None,
                        "publish_date": row.get("publish_date", "")
                    }
                    
                    # Skip rows with invalid blog_id
                    if entry["blog_id"] is None:
                        print(f"Warning: Skipping row {row_num} - invalid blog_id")
                        continue
                    
                    self.correlation_data.append(entry)
                    count += 1
                except (ValueError, KeyError) as e:
                    print(f"Warning: Skipping row {row_num} - error parsing: {e}")
                    continue
        
        print(f"Loaded {count} entries from BlogCluster.csv")

    def clean_output_directory(self) -> None:
        """Remove all existing files and directories in the output directory."""
        if not self.restart:
            return
            
        if self.output_dir.exists():
            print(f"Cleaning output directory: {self.output_dir}")
            shutil.rmtree(self.output_dir)
            print("Output directory cleaned successfully")
        else:
            print(f"Output directory does not exist: {self.output_dir}")

    def generate_prompts_for_csc_tap_mla(self) -> None:
        """Generate prompts for CSC/TAP/MLA tasks using BlogCluster.csv and blog corpus."""
        if not self.template:
            raise RuntimeError("Template not loaded. Call load_template() first.")

        # Load the preprocessed-reports corpus to use the `preprocessed` field as each cluster's text
        print("Loading preprocessed-reports corpus data...")
        blog_entries = self.load_preprocessed_reports_corpus()

        total_pairs = 0
        generated_pairs = 0
        saved_pairs = 0

        print(f"Generating {self.task.upper()} prompts from BlogCluster data...")

        # Group entries by object_id
        object_groups = {}
        for entry in self.correlation_data:
            object_id = entry["object_id"]
            if object_id not in object_groups:
                object_groups[object_id] = []
            object_groups[object_id].append(entry)

        for object_id, entries in object_groups.items():
            # Determine task type based on the first entry's type
            entry_type = entries[0]["type"]
            
            if self.task == "csc" and entry_type in ["event", "campaign"]:
                # CSC task for event/campaign types - generates 4 prompts (one per aspect)
                self._generate_csc_prompt(entries, blog_entries, object_id)
                total_pairs += 4  # CSC generates 4 prompts per object group
            elif self.task == "tap" and entry_type == "threat actor":
                # TAP task for threat actor types - generates 3 prompts (one per aspect)
                self._generate_tap_prompt(entries, blog_entries, object_id)
                total_pairs += 3  # TAP generates 3 prompts per object group
            elif self.task == "mla" and entry_type == "malware":
                # MLA task for malware types - generates 2 prompts (one per aspect)
                self._generate_mla_prompt(entries, blog_entries, object_id)
                total_pairs += 2  # MLA generates 2 prompts per object group

        print(f"\n{self.task.upper()} generation complete:")
        print(f"  Total object groups: {total_pairs}")
        print(f"  Successfully generated: {generated_pairs}")
        print(f"  Successfully saved: {saved_pairs}")
        print(f"  Output directory: {self.output_dir}")

    def _generate_csc_prompt(self, entries, blog_entries, object_id):
        """Generate CSC prompt for event/campaign types with aspect rotation."""
        # Sort entries by publish_date in descending order (latest first)
        sorted_entries = sorted(entries, key=lambda x: x["publish_date"], reverse=True)
        
        # Get the latest entry as source (chronologically most recent)
        source_entry = sorted_entries[0]
        source_blog = blog_entries.get(str(source_entry["blog_id"]))
        
        if not source_blog:
            print(f"Warning: Blog entry {source_entry['blog_id']} not found for object {object_id}")
            return

        # Create simplified source node with blog_id and text (preprocessed field)
        source_node = {
            "blog_id": f"BLOG-{source_entry['blog_id']}",
            "text": source_blog.get("preprocessed", "")
        }

        # Get all other entries as target blogs (chronologically earlier)
        target_blogs = []
        blog_ids = [str(source_entry["blog_id"])]  # Start with source blog ID
        
        for entry in sorted_entries[1:]:  # Skip the first entry (source)
            blog = blog_entries.get(str(entry["blog_id"]))
            if blog:
                target_node = {
                    "blog_id": f"BLOG-{entry['blog_id']}",
                    "text": blog.get("preprocessed", "")
                }
                target_blogs.append(target_node)  # Pass the dict directly, not JSON string
                blog_ids.append(str(entry["blog_id"]))

        if not target_blogs:
            print(f"Warning: No target blogs found for object {object_id}")
            return

        # Define the aspects for CSC - auto-detect from template, fallback to version-based
        if hasattr(self, 'detected_aspects') and self.detected_aspects:
            aspects = self.detected_aspects
        elif self.template_version == "v7":
            aspects = ["initial_access", "execution", "persistence", "impact"]
        else:
            aspects = ["entities", "dates", "targeting", "tool"]
        
        # Generate prompts for each aspect
        for aspect in aspects:
            try:
                prompt = self.template.render(
                    SOURCE_NODE=source_node,  # Pass the dict directly, not JSON string
                    TARGET_NODES=target_blogs,
                    ASPECT=aspect
                )
                
                if prompt:
                    # Create filename with blog IDs and aspect: BLOG-1-BLOG-2-BLOG-3-entities
                    display_id = "-".join([f"BLOG-{bid}" for bid in blog_ids]) + f"-{aspect}"
                    if self.save_prompt(prompt, display_id):
                        print(f"Generated CSC prompt for object {object_id} ({aspect}): {source_entry['title']}")
                        
            except Exception as e:
                print(f"Error rendering CSC template for object {object_id} ({aspect}): {e}", file=sys.stderr)

    def _generate_tap_prompt(self, entries, blog_entries, object_id):
        """Generate TAP prompt for threat actor types with aspect rotation."""
        # Sort entries by publish_date in descending order (latest first)
        sorted_entries = sorted(entries, key=lambda x: x["publish_date"], reverse=True)
        
        # Get the latest entry as source (chronologically most recent)
        source_entry = sorted_entries[0]
        source_blog = blog_entries.get(str(source_entry["blog_id"]))
        
        if not source_blog:
            print(f"Warning: Blog entry {source_entry['blog_id']} not found for object {object_id}")
            return

        # Create simplified source node with blog_id and text (preprocessed field)
        source_node = {
            "blog_id": f"BLOG-{source_entry['blog_id']}",
            "text": source_blog.get("preprocessed", "")
        }

        # Get all other entries as target blogs (chronologically earlier)
        target_blogs = []
        blog_ids = [str(source_entry["blog_id"])]  # Start with source blog ID
        
        for entry in sorted_entries[1:]:  # Skip the first entry (source)
            blog = blog_entries.get(str(entry["blog_id"]))
            if blog:
                target_node = {
                    "blog_id": f"BLOG-{entry['blog_id']}",
                    "text": blog.get("preprocessed", "")
                }
                target_blogs.append(target_node)  # Pass the dict directly, not JSON string
                blog_ids.append(str(entry["blog_id"]))

        if not target_blogs:
            print(f"Warning: No target blogs found for object {object_id}")
            return

        # Define the aspects for TAP - auto-detect from template, fallback to version-based
        if hasattr(self, 'detected_aspects') and self.detected_aspects:
            aspects = self.detected_aspects
        elif self.template_version == "v3":
            aspects = ["infrastructure", "motivation", "impact"]
        else:
            aspects = ["actor", "tool", "target"]
        
        # Generate prompts for each aspect
        for aspect in aspects:
            try:
                prompt = self.template.render(
                    SOURCE_NODE=source_node,  # Pass the dict directly, not JSON string
                    TARGET_NODES=target_blogs,
                    ASPECT=aspect
                )
                
                if prompt:
                    # Create filename with blog IDs and aspect: BLOG-1-BLOG-2-BLOG-3-actor
                    display_id = "-".join([f"BLOG-{bid}" for bid in blog_ids]) + f"-{aspect}"
                    if self.save_prompt(prompt, display_id):
                        print(f"Generated TAP prompt for object {object_id} ({aspect}): {source_entry['title']}")
                        
            except Exception as e:
                print(f"Error rendering TAP template for object {object_id} ({aspect}): {e}", file=sys.stderr)

    def _generate_mla_prompt(self, entries, blog_entries, object_id):
        """Generate MLA prompt for malware types with aspect rotation."""
        # Sort entries by publish_date in descending order (latest first)
        sorted_entries = sorted(entries, key=lambda x: x["publish_date"], reverse=True)
        
        # Get the latest entry as source (chronologically most recent)
        source_entry = sorted_entries[0]
        source_blog = blog_entries.get(str(source_entry["blog_id"]))
        
        if not source_blog:
            print(f"Warning: Blog entry {source_entry['blog_id']} not found for object {object_id}")
            return

        # Create simplified source node with blog_id and text (preprocessed field)
        source_node = {
            "blog_id": f"BLOG-{source_entry['blog_id']}",
            "text": source_blog.get("preprocessed", "")
        }

        # Get all other entries as target blogs (chronologically earlier)
        target_blogs = []
        blog_ids = [str(source_entry["blog_id"])]  # Start with source blog ID
        
        for entry in sorted_entries[1:]:  # Skip the first entry (source)
            blog = blog_entries.get(str(entry["blog_id"]))
            if blog:
                target_node = {
                    "blog_id": f"BLOG-{entry['blog_id']}",
                    "text": blog.get("preprocessed", "")
                }
                target_blogs.append(target_node)  # Pass the dict directly, not JSON string
                blog_ids.append(str(entry["blog_id"]))

        if not target_blogs:
            print(f"Warning: No target blogs found for object {object_id}")
            return

        # Define the aspects for MLA - auto-detect from template, fallback to version-based
        if hasattr(self, 'detected_aspects') and self.detected_aspects:
            aspects = self.detected_aspects
        elif self.template_version == "v3":
            aspects = ["distribution", "targeting"]
        else:
            aspects = ["variant", "capability"]
        
        # Generate prompts for each aspect
        for aspect in aspects:
            try:
                prompt = self.template.render(
                    SOURCE_NODE=source_node,  # Pass the dict directly, not JSON string
                    TARGET_NODES=target_blogs,
                    ASPECT=aspect
                )
                
                if prompt:
                    # Create filename with blog IDs and aspect: BLOG-1-BLOG-2-BLOG-3-variant
                    display_id = "-".join([f"BLOG-{bid}" for bid in blog_ids]) + f"-{aspect}"
                    if self.save_prompt(prompt, display_id):
                        print(f"Generated MLA prompt for object {object_id} ({aspect}): {source_entry['title']}")
                        
            except Exception as e:
                print(f"Error rendering MLA template for object {object_id} ({aspect}): {e}", file=sys.stderr)

    def extract_aspects_from_template(self, template_path: Path) -> List[str]:
        """
        Extract ASPECT values from Jinja2 template by parsing {% if ASPECT == "xxx" %} conditions.
        
        Args:
            template_path: Path to the template file
        Returns:
            List of aspect values found in the template
        """
        aspects = []
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Match patterns like: {% if ASPECT == "aspect_name" %} or {% elif ASPECT == "aspect_name" %}
            pattern = r'{%\s*(?:if|elif)\s+ASPECT\s*==\s*"([^"]+)"\s*%}'
            matches = re.findall(pattern, content)
            aspects = list(set(matches))  # Remove duplicates and convert to list
            
        except Exception as e:
            print(f"Warning: Could not extract aspects from template: {e}", file=sys.stderr)
        
        return sorted(aspects)  # Return sorted list for consistency
    
    def load_template(self) -> None:
        """Load and compile the Jinja2 template."""
        # Path structure: templates/{task}/{aspect}/{version}.jinja or templates/{task}/{version}.jinja
        # if self.aspect:
            # template_dir_path = self.template_dir / self.task / self.aspect
        # else:
        template_dir_path = self.template_dir / self.task
        template_file_name = f"{self.template_version}.jinja"
        template_file_path = template_dir_path / template_file_name
        
        print(f"Loading template from {template_file_path}...")
        
        if not template_file_path.exists():
            raise FileNotFoundError(f"Template file not found: {template_file_path}")
        
        # Extract aspects from template for auto-detection
        self.detected_aspects = self.extract_aspects_from_template(template_file_path)
        if self.detected_aspects:
            print(f"Detected aspects in template: {', '.join(self.detected_aspects)}")
        
        # Set up Jinja2 environment
        env = Environment(loader=FileSystemLoader(str(template_dir_path)))
        
        # Load template
        self.template = env.get_template(template_file_name)
        
        print("Template loaded successfully")
        
    def get_target_entry_without_id(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get target entry without the 'id' field to avoid conflicts.
        
        Args:
            entry: Original entry dictionary
        Returns:
            Entry dictionary without the 'id' field
        """
        if entry is None:
            return None
        
        # Create a copy of the entry without the 'id' field
        clean_entry = entry.copy()
        clean_entry.pop('id', None)
        clean_entry.pop('capec_id', None)
        clean_entry.pop('cwe_id', None)
        clean_entry.pop('mitre_id', None)
        clean_entry.pop('cve_id', None)
        
        return clean_entry

    def filter_node_to_basic_fields(self, entry: Dict[str, Any], entry_type: str) -> Dict[str, Any]:
        """
        Filter node to only include id, name, and description fields.
        
        Args:
            entry: Original entry dictionary
            entry_type: Type of entry (cve, cwe, mitre, etc.)
        Returns:
            Filtered entry dictionary with only id, name, description
        """
        if entry is None:
            return None
        
        filtered_entry = {}
        
        # Add basic ID field
        if entry_type == "cve":
            filtered_entry["id"] = entry.get("cve_id", "")
            filtered_entry["name"] = entry.get("title", "")
        elif entry_type == "cwe":
            filtered_entry["id"] = entry.get("cwe_id", "")
            filtered_entry["name"] = entry.get("title", "")
        elif entry_type == "mitre":
            filtered_entry["id"] = entry.get("mitre_id", "")
            filtered_entry["name"] = entry.get("title", "")
        elif entry_type == "capec":
            capec_id = entry.get("capec_id", "")
            filtered_entry["id"] = f"CAPEC-{capec_id}" if capec_id and not str(capec_id).startswith("CAPEC-") else capec_id
            filtered_entry["name"] = entry.get("title", "")
        else:
            # Generic fallback
            filtered_entry["id"] = entry.get("id", "")
            filtered_entry["name"] = entry.get("name", entry.get("title", ""))
        
        # Extract description from contents if available
        contents_str = entry.get("contents")
        if contents_str:
            try:
                contents = json.loads(contents_str)
                if "descriptions" in contents and contents["descriptions"]:
                    # Get the first English description
                    for desc in contents["descriptions"]:
                        if desc.get("lang") == "en":
                            filtered_entry["description"] = desc.get("value", "")
                            break
                    # If no English description found, use the first one
                    if "description" not in filtered_entry and contents["descriptions"]:
                        filtered_entry["description"] = contents["descriptions"][0].get("value", "")
                elif "Description" in contents:
                    filtered_entry["description"] = contents["Description"]
                else:
                    filtered_entry["description"] = ""
            except json.JSONDecodeError:
                filtered_entry["description"] = ""
        else:
            filtered_entry["description"] = ""
        
        return filtered_entry
        
    def generate_prompt(self, source_node, target_node, aspect_name) -> Optional[str]:
        """
        Generate a prompt for a given relationship.

        Args:
            source_node: Source node dictionary
            target_node: Target node dictionary
        Returns:
            Generated prompt string or None if generation fails
        """
        if not source_node or not target_node:
            return None

        try:
            prompt = self.template.render(
                SOURCE_NODE=json.dumps(source_node, indent=2),
                TARGET_NODE=json.dumps(target_node, indent=2),
                ASPECT=aspect_name,
            )
            return prompt
        except Exception as e:
            print(f"Error rendering template: {e}", file=sys.stderr)
            return None
    
    def save_prompt(self, prompt: str, source_id: str, target_id: str = None) -> bool:
        """
        Save a generated prompt to file.
        
        Args:
            prompt: Generated prompt content
            source_id: Source node ID
            target_id: Target node ID (optional)
            
        Returns:
            True if saved successfully, False otherwise
        """
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        if target_id:
            filename = f"{source_id}-{target_id}.txt"
        else:
            filename = f"{source_id}.txt"
            
        output_path = self.output_dir / filename
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(prompt)
            return True
        except Exception as e:
            print(f"Error saving prompt to {output_path}: {e}", file=sys.stderr)
            return False

    
    def _process_rcm_pair(self, correlation, source_node_id, target_node_id, index):
        """Process a single RCM pair (CVE -> CWE)."""
        # Get source entry
        source_entry = self.source_entries.get(source_node_id)
        if not source_entry:
            print(f"Warning: Source entry not found for CVE {source_node_id}", file=sys.stderr)
            return

        # Get target entry
        target_entry = self.target_entries.get(target_node_id)
        if not target_entry:
            print(f"Warning: Target entry not found for CWE {target_node_id} (source {source_node_id})", file=sys.stderr)
            return

        # Define aspects for RCM task
        aspects = [
            "description",
            "weaknesses", 
            "common_consequences",
            "detection_methods",
            "potential_mitigations"
        ]
        
        # Cycle through aspects
        aspect_index = index % len(aspects)
        aspect = aspects[aspect_index]
        
        # For RCM task, filter both source and target nodes to only include id, name, description
        source_node = self.filter_node_to_basic_fields(source_entry, "cve")
        target_node = self.filter_node_to_basic_fields(target_entry, "cwe")

        # Generate prompt
        prompt = self.generate_prompt(source_node, target_node, aspect)
        if prompt:
            # Format identifiers for filename
            display_source_id = f"CVE-{source_node_id}" if not source_node_id.startswith("CVE-") else source_node_id
            display_target_id = f"CWE-{target_node_id}" if not target_node_id.startswith("CWE-") else target_node_id
            
            if self.save_prompt(prompt, display_source_id, display_target_id):
                print(f"Generated RCM prompt: {display_source_id} -> {display_target_id} ({aspect})")

    def generate_all_prompts(self, task: str) -> None:
        """Generate prompts for all correlation pairs."""
        if not self.template:
            raise RuntimeError("Template not loaded. Call load_template() first.")
        
        total_pairs = 0
        generated_pairs = 0
        saved_pairs = 0
        
        print(f"Generating prompts for {task}...")

        if self.task == "vca":
            correlated_key = "cwe_id"
        elif self.task == "ata":
            correlated_key = "technique_id"
        elif self.task == "rcm":
            correlated_key = "correlated_cwe"
        elif self.task == "wim":
            correlated_key = "correlated_cve"
        elif self.task == "atd":
            correlated_key = "correlated_mitre"
        elif self.task == "esd":
            correlated_key = "correlated_capec"

        for index, correlation in enumerate(self.correlation_data):
            source_node_id = correlation.get(f'{self.source_type}_id')
            target_node_id = correlation.get(correlated_key)
            source_node_id = str(source_node_id)
            
            # Handle RCM task specially since correlated_cwe is a list
            if self.task == "rcm":
                correlated_cwe_list = correlation.get("correlated_cwe", [])
                if not correlated_cwe_list:
                    continue
                # Process each CWE in the list
                for cwe_entry in correlated_cwe_list:
                    cwe_id = cwe_entry.get("cwe_id")
                    if not cwe_id:
                        continue
                    target_node_id = str(cwe_id)
                    self._process_rcm_pair(correlation, source_node_id, target_node_id, index)
                continue
            
            # Handle WIM task specially since correlated_cve is a list
            if self.task == "wim":
                correlated_cve_list = correlation.get("correlated_cve", [])
                if not correlated_cve_list:
                    continue
                # Process each CVE in the list
                for cve_entry in correlated_cve_list:
                    cve_id = cve_entry.get("cve_id")
                    if not cve_id:
                        continue
                    target_node_id = str(cve_id)
                    # For WIM task, filter both source and target nodes to basic fields
                    source_entry = self.source_entries.get(source_node_id)
                    target_entry = self.target_entries.get(target_node_id)
                    if not source_entry or not target_entry:
                        continue
                    source_node = self.filter_node_to_basic_fields(source_entry, self.source_type)
                    target_node = self.filter_node_to_basic_fields(target_entry, self.target_type)
                    
                    # Generate prompt directly for WIM task
                    prompt = self.generate_prompt(source_node, target_node, "")
                    if prompt:
                        generated_pairs += 1
                        display_source_id = f"CWE-{source_node_id}" if not source_node_id.startswith("CWE-") else source_node_id
                        display_target_id = f"CVE-{target_node_id}" if not target_node_id.startswith("CVE-") else target_node_id
                        if self.save_prompt(prompt, display_source_id, display_target_id):
                            saved_pairs += 1
                            if saved_pairs % 50 == 0:
                                print(f"Progress: {saved_pairs}/{total_pairs} prompts saved")
                continue
            
            # Handle ATD task specially since correlated_mitre is a list
            if self.task == "atd":
                correlated_mitre_list = correlation.get("correlated_mitre", [])
                if not correlated_mitre_list:
                    continue
                # Process each MITRE technique in the list
                for mitre_entry in correlated_mitre_list:
                    mitre_id = mitre_entry.get("mitre_id")
                    if not mitre_id:
                        continue
                    # Add T prefix if not present
                    target_node_id = f"T{mitre_id}" if not str(mitre_id).startswith("T") else str(mitre_id)
                    # For ATD task, filter both source and target nodes to basic fields
                    source_entry = self.source_entries.get(source_node_id)
                    target_entry = self.target_entries.get(target_node_id)
                    if not source_entry or not target_entry:
                        continue
                    source_node = self.filter_node_to_basic_fields(source_entry, self.source_type)
                    target_node = self.filter_node_to_basic_fields(target_entry, self.target_type)
                    
                    # Generate prompt directly for ATD task
                    prompt = self.generate_prompt(source_node, target_node, "")
                    if prompt:
                        generated_pairs += 1
                        display_source_id = f"CAPEC-{source_node_id}" if not source_node_id.startswith("CAPEC-") else source_node_id
                        display_target_id = f"T{target_node_id}" if not target_node_id.startswith("T") else target_node_id
                        if self.save_prompt(prompt, display_source_id, display_target_id):
                            saved_pairs += 1
                            if saved_pairs % 50 == 0:
                                print(f"Progress: {saved_pairs}/{total_pairs} prompts saved")
                continue
            
            # Handle ESD task specially since correlated_capec is a list
            if self.task == "esd":
                correlated_capec_list = correlation.get("correlated_capec", [])
                if not correlated_capec_list:
                    continue
                # Process each CAPEC in the list
                for capec_entry in correlated_capec_list:
                    capec_id = capec_entry.get("capec_id")
                    if not capec_id:
                        continue
                    target_node_id = str(capec_id)
                    # For ESD task, filter both source and target nodes to basic fields
                    source_entry = self.source_entries.get(source_node_id)
                    target_entry = self.target_entries.get(target_node_id)
                    if not source_entry or not target_entry:
                        continue
                    source_node = self.filter_node_to_basic_fields(source_entry, self.source_type)
                    target_node = self.filter_node_to_basic_fields(target_entry, self.target_type)
                    
                    # Generate prompt directly for ESD task
                    prompt = self.generate_prompt(source_node, target_node, "")
                    if prompt:
                        generated_pairs += 1
                        display_source_id = f"CWE-{source_node_id}" if not source_node_id.startswith("CWE-") else source_node_id
                        display_target_id = f"CAPEC-{target_node_id}" if not target_node_id.startswith("CAPEC-") else target_node_id
                        if self.save_prompt(prompt, display_source_id, display_target_id):
                            saved_pairs += 1
                            if saved_pairs % 50 == 0:
                                print(f"Progress: {saved_pairs}/{total_pairs} prompts saved")
                continue
            
            # Normalize target id based on task
            if self.task == "vca":
                # For CWE, keep only digits (remove CWE- prefix)
                target_node_id = re.sub(r'[^\d]', '', str(target_node_id))
            elif self.task == "ata":
                # For MITRE ATT&CK, preserve the leading 'T' and optional sub-technique suffix
                # Use helper to robustly extract ID (e.g., "T1059.001")
                target_node_id = self._extract_mitre_id_from_technique(str(target_node_id))

            # Get source entry
            source_entry = self.source_entries.get(source_node_id)

            # get target entry
            target_entry = self.target_entries.get(target_node_id)
            if not target_entry:
                print(f"Warning: Target entry not found for {self.task} id {target_node_id} (source {source_node_id})", file=sys.stderr)
                continue
            
            if self.task == "vca" or self.task == "ata":
                source_node = correlation.get("attack_behavior_text")
            elif self.task in ["rcm", "wim", "atd", "esd"]:
                # For rcm/wim/atd/esd tasks, filter both source and target nodes to basic fields
                source_node = self.filter_node_to_basic_fields(source_entry, self.source_type)
                target_node = self.filter_node_to_basic_fields(target_entry, self.target_type)
                
                # Generate prompt directly for these tasks
                prompt = self.generate_prompt(source_node, target_node, "")
                if prompt:
                    generated_pairs += 1
                    display_source_id = f"{self.source_type.upper()}-{source_node_id}" if not source_node_id.startswith(self.source_type.upper()) else source_node_id
                    display_target_id = f"{self.target_type.upper()}-{target_node_id}" if not target_node_id.startswith(self.target_type.upper()) else target_node_id
                    if self.save_prompt(prompt, display_source_id, display_target_id):
                        saved_pairs += 1
                        if saved_pairs % 50 == 0:
                            print(f"Progress: {saved_pairs}/{total_pairs} prompts saved")
                continue
            
            if self.task == "vca":
                aspects = [
                    "Applicable_Platforms",
                    "Modes_Of_Introduction",
                    "Likelihood_Of_Exploit",
                    "Common_Consequences",
                    "Detection_Methods",
                    "Potential_Mitigations"
                ]
            elif self.task == "ata":
                aspects = [
                    "kill_chain_phases",
                    "x_mitre_detection",
                    "x_mitre_platforms",
                    "x_mitre_data_sources"
                ]
            aspect_index = index % len(aspects)
            aspect = aspects[aspect_index]
            contents_str = target_entry.get("contents")
            try:
                content_aspect = json.loads(contents_str).get(aspect)
                target_node = target_entry.copy()
                target_node["contents"] = {f"{aspect}": content_aspect}
            except json.JSONDecodeError:
                raise ValueError(f"Failed to parse contents JSON for target entry {target_node_id}")
            prompt = self.generate_prompt(source_node, target_node, aspect)
            if prompt:
                generated_pairs += 1
                display_source_id, display_target_id = self.format_identifier(self.task, source_node_id, target_node_id)
                if self.save_prompt(prompt, display_source_id, display_target_id):
                    saved_pairs += 1
                    if saved_pairs % 50 == 0:
                        print(f"Progress: {saved_pairs}/{total_pairs} prompts saved")

        
        print(f"\nGeneration complete:")
        print(f"  Total correlation pairs: {total_pairs}")
        print(f"  Successfully generated: {generated_pairs}")
        print(f"  Successfully saved: {saved_pairs}")
        print(f"  Output directory: {self.output_dir}")
    
    def create_batches(self) -> None:
        """Create random batches from generated prompts."""
        if not self.output_dir.exists():
            print("No prompts found to batch")
            return
        
        # Get all prompt files
        prompt_files = [f for f in self.output_dir.iterdir() if f.is_file() and f.suffix == '.txt']
        total_files = len(prompt_files)
        
        if total_files == 0:
            print("No prompt files found to batch")
            return
        
        print(f"Creating batches from {total_files} prompt files...")
        
        # Shuffle files randomly
        random.shuffle(prompt_files)
        
        # Calculate number of full batches and remaining files
        num_full_batches = total_files // self.batch_size
        remaining_files = total_files % self.batch_size
        
        # Create batch directories
        batches_created = 0
        
        # Create batch_1 to batch_N (full batches of batch_size each)
        for batch_id in range(1, num_full_batches + 1):
            batch_dir = self.output_dir / f"batch_{batch_id}"
            batch_dir.mkdir(exist_ok=True)
            
            # Get files for this batch
            start_idx = (batch_id - 1) * self.batch_size
            end_idx = start_idx + self.batch_size
            batch_files = prompt_files[start_idx:end_idx]
            
            # Move files to batch directory (do not keep loose files in root)
            for file_path in batch_files:
                shutil.move(str(file_path), str(batch_dir / file_path.name))
            
            print(f"  Created batch_{batch_id}: {len(batch_files)} files")
            batches_created += 1
        
        # Create batch_0 for remaining files (if any)
        if remaining_files > 0:
            batch_0_dir = self.output_dir / "batch_0"
            batch_0_dir.mkdir(exist_ok=True)
            
            # Get remaining files
            start_idx = num_full_batches * self.batch_size
            batch_0_files = prompt_files[start_idx:]
            
            # Move files to batch_0 directory (do not keep loose files in root)
            for file_path in batch_0_files:
                shutil.move(str(file_path), str(batch_0_dir / file_path.name))
            
            print(f"  Created batch_0: {len(batch_0_files)} files")
            batches_created += 1
        
        # Summary
        print(f"Batching complete:")
        print(f"  Total files: {total_files}")
        print(f"  Batches created: {batches_created}")
        if remaining_files > 0:
            print(f"  Full batches (batch_1 to batch_{num_full_batches}): {self.batch_size} files each")
            print(f"  Remainder batch (batch_0): {remaining_files} files")
        else:
            print(f"  All batches (batch_1 to batch_{num_full_batches}): {self.batch_size} files each")
    
    def run(self) -> None:
        """Run the complete prompt generation process."""
        try:
            self.load_correlation_data(self.task)
            self.load_template()
            self.clean_output_directory()
            self.output_dir.mkdir(parents=True, exist_ok=True)

            if self.task in ["csc", "tap", "mla"]:
                self.generate_prompts_for_csc_tap_mla()
            elif self.task == "ata":
                self.source_type = "blog"
                self.target_type = "mitre"
                print(f"Loading corpus data for {self.source_type}")
                self.source_entries = self.load_corpus_data(self.source_type)
                print(f"Loading corpus data for {self.target_type}")
                self.target_entries = self.load_corpus_data(self.target_type)
                self.generate_all_prompts(self.task)
            elif self.task == "vca":
                self.generate_prompts_for_vca()
            elif self.task == "rcm":
                self.source_type = "cve"
                self.target_type = "cwe"
                print(f"Loading corpus data for {self.source_type}")
                self.source_entries = self.load_corpus_data(self.source_type)
                print(f"Loading original corpus data for {self.target_type}")
                self.target_entries = self.load_original_cwe_data()
                self.generate_all_prompts(self.task)
            elif self.task == "wim":
                self.source_type = "cwe"
                self.target_type = "cve"
                print(f"Loading original corpus data for {self.source_type}")
                self.source_entries = self.load_original_cwe_data()
                print(f"Loading corpus data for {self.target_type}")
                self.target_entries = self.load_corpus_data(self.target_type)
                self.generate_all_prompts(self.task)
            elif self.task == "atd":
                self.source_type = "capec"
                self.target_type = "mitre"
                print(f"Loading corpus data for {self.source_type}")
                self.source_entries = self.load_corpus_data(self.source_type)
                print(f"Loading corpus data for {self.target_type}")
                self.target_entries = self.load_corpus_data(self.target_type)
                self.generate_all_prompts(self.task)
            elif self.task == "esd":
                self.source_type = "cwe"
                self.target_type = "capec"
                print(f"Loading original corpus data for {self.source_type}")
                self.source_entries = self.load_original_cwe_data()
                print(f"Loading corpus data for {self.target_type}")
                self.target_entries = self.load_corpus_data(self.target_type)
                self.generate_all_prompts(self.task)

            if self.enable_batching:
                print("\nCreating batches...")
                self.create_batches()

        except Exception as e:
            print(f"Error during prompt generation: {e}", file=sys.stderr)
            sys.exit(1)