#!/usr/bin/env python3
"""
LLM Annotator - LLM-powered CWE or MITRE annotation for B2F repository
"""

import json
import sys
import time
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))
from utils.file_utils import load_jsonl, save_jsonl, file_exists
from utils.llm_utils import setup_openai_client, call_llm_api, get_cwe_mapping_prompt, print_llm_call_summary
from config.settings import *

class LLMAnnotator:
    """LLM-powered CWE or MITRE annotation using vector retrieval and LLM judgment"""
    
    def __init__(self, framework: str = "cwe", force_restart: bool = False):
        """Initialize the LLM annotator"""
        self.framework = framework.lower()
        self.client = setup_openai_client()
        self.force_restart = force_restart
        
        if self.framework == "mitre":
            self.input_file = BLOG_MITRE_BEHAVIOR_ID
            self.corpus_file = MITRE_CORPUS_FILE
            self.output_file = BLOG_MITRE_LLM_ENRICHED
        elif self.framework == "capec":
            self.input_file = BLOG_CAPEC_BEHAVIOR_ID
            self.corpus_file = CAPEC_CORPUS_FILE
            self.output_file = BLOG_CAPEC_LLM_ENRICHED
        elif self.framework == "cve":
            self.input_file = BLOG_CVE_BEHAVIOR_ID
            self.corpus_file = CVE_CORPUS_FILE
            self.output_file = BLOG_CVE_LLM_ENRICHED
        else:  # cwe (default)
            self.input_file = BLOG_CWE_BEHAVIOR_ID
            self.corpus_file = CWE_CORPUS_FILE
            self.output_file = BLOG_CWE_LLM_ENRICHED
        
        # Setup checkpoint file
        self.checkpoint_file = CHECKPOINT_FILE.parent / f"llm_annotator_{self.framework}.json"
        
        print(f"📁 Framework: {self.framework.upper()}")
        print(f"📁 Input file: {self.input_file}")
        print(f"📁 Corpus file: {self.corpus_file}")
        print(f"📁 Output file: {self.output_file}")
        print(f"📁 Checkpoint file: {self.checkpoint_file}")
        
        # Load corpus
        self.corpus = self.load_corpus()
        
        # Initialize embedding manager and pre-compute corpus embeddings
        self.initialize_embeddings()
        
        # Initialize checkpoint state
        self.checkpoint_state = self.load_checkpoint()
        
        # Note: We no longer load existing annotations since we save incrementally
        # self.existing_annotations = self.load_existing_annotations()
    
    def load_corpus(self) -> Dict[str, Any]:
        """Load corpus for reference"""
        print(f"📁 Loading {self.framework.upper()} corpus...")
        
        if not file_exists(str(self.corpus_file)):
            print(f"❌ Corpus file not found: {self.corpus_file}")
            return {}
        
        corpus_data = {}
        try:
            with open(self.corpus_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line.strip())
                        # For CVE, use cve_id as key; for others, use id
                        if self.framework == "cve":
                            entry_id = entry.get('cve_id', '')
                            if not entry_id:
                                # Fallback: try to extract from contents
                                try:
                                    if isinstance(entry.get('contents'), str):
                                        contents = json.loads(entry.get('contents', '{}'))
                                        entry_id = contents.get('id', '')
                                except:
                                    pass
                        else:
                            entry_id = entry.get('id', '')
                        
                        if entry_id:
                            # Normalize CVE ID (remove CVE- prefix for key, but keep it in entry)
                            if self.framework == "cve" and entry_id.startswith('CVE-'):
                                corpus_data[entry_id] = entry  # Use full CVE-XXXX-XXXX as key
                                corpus_data[entry_id.replace('CVE-', '')] = entry  # Also index without prefix
                            else:
                                corpus_data[entry_id] = entry
            
            # Count unique entries (since we may have multiple keys pointing to same entry)
            unique_entries = len(set(id(entry) for entry in corpus_data.values()))
            print(f"✅ Loaded {unique_entries} {self.framework.upper()} entries from corpus")
            return corpus_data
            
        except Exception as e:
            print(f"❌ Error loading {self.framework.upper()} corpus: {e}")
            return {}
    
    def initialize_embeddings(self):
        """Initialize embedding manager and pre-compute corpus embeddings"""
        print("🚀 Initializing embedding system...")
        
        from utils.embedding_utils import create_embedding_manager
        
        try:
            self.embedding_manager = create_embedding_manager()
            
            # Convert corpus to list format for similarity search
            corpus_entries = []
            for entry_id, entry in self.corpus.items():
                if self.framework == "mitre":
                    # Parse contents JSON to get description
                    contents_json = entry.get('contents', '{}')
                    try:
                        contents_data = json.loads(contents_json)
                        description = contents_data.get('description', '')
                    except (json.JSONDecodeError, TypeError):
                        description = ''
                    
                    corpus_entries.append({
                        'id': entry_id,
                        'title': entry.get('title', ''),
                        'contents': description
                    })
                elif self.framework == "capec":
                    # Parse CAPEC contents to get description
                    description = "No description"
                    try:
                        if "_full_content" in entry:
                            description = entry["_full_content"]
                        elif "contents" in entry:
                            try:
                                contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                                if isinstance(contents_data, dict):
                                    if "Description" in contents_data:
                                        description = contents_data["Description"]
                                    elif "Summary" in contents_data:
                                        description = contents_data["Summary"]
                            except json.JSONDecodeError:
                                pass
                        elif "description" in entry:
                            description = entry["description"]
                    except Exception:
                        pass
                    corpus_entries.append({
                        'id': entry_id,
                        'name': entry.get('title', entry.get('name', '')),
                        'description': description
                    })
                elif self.framework == "cve":
                    # Parse CVE contents to get description
                    description = "No description"
                    try:
                        if "_full_content" in entry:
                            description = entry["_full_content"]
                        elif "contents" in entry:
                            try:
                                contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                                if isinstance(contents_data, dict):
                                    if "Description" in contents_data:
                                        description = contents_data["Description"]
                                    elif "description" in contents_data:
                                        description = contents_data["description"]
                            except json.JSONDecodeError:
                                pass
                        elif "description" in entry:
                            description = entry["description"]
                    except Exception:
                        pass
                    corpus_entries.append({
                        'id': entry_id,
                        'name': entry.get('title', entry.get('name', '')),
                        'description': description
                    })
                else:  # cwe
                    # Use robust description extraction consistent with annotate_dataset.py
                    description = "No description"
                    try:
                        if "_full_content" in entry:
                            description = entry["_full_content"]
                        elif "contents" in entry:
                            try:
                                contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                                if isinstance(contents_data, dict):
                                    if "Description" in contents_data:
                                        description = contents_data["Description"]
                                    elif "Summary" in contents_data:
                                        description = contents_data["Summary"]
                                    elif "@Name" in contents_data:
                                        description = contents_data["@Name"]
                            except json.JSONDecodeError:
                                pass
                        elif "description" in entry:
                            description = entry["description"]
                    except Exception:
                        pass
                    corpus_entries.append({
                        'id': entry_id,
                        'name': entry.get('title', entry.get('name', '')),
                        'description': description
                    })
            
            # Pre-compute embeddings for all corpus entries
            text_field = 'contents' if self.framework == "mitre" else 'description'
            self.embedding_manager.precompute_corpus_embeddings(
                corpus_entries, 
                framework=self.framework,
                text_field=text_field
            )
            
            print("✅ Embedding system initialized successfully")
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to initialize embedding system: {e}")
            self.embedding_manager = None
    
    def load_checkpoint(self) -> Dict[str, Any]:
        """Load checkpoint state from file"""
        if self.force_restart or not self.checkpoint_file.exists():
            print("🔄 Starting fresh (no checkpoint or force restart)")
            return {
                'framework': self.framework,
                'blog_id': None,
                'behavior_id': None,
                'last_processed_blog_id': None,
                'last_processed_behavior_id': None,
                'processed_techniques': 0,
                'total_techniques': 0,
                'total_blogs_processed': 0,
                'total_annotations_generated': 0,
                'start_time': datetime.now().isoformat(),
                'last_update': datetime.now().isoformat(),
                'status': 'initialized'
            }
        
        try:
            with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)
            
            # Validate checkpoint
            if checkpoint.get('framework') != self.framework:
                print("⚠️  Checkpoint framework mismatch, starting fresh")
                return self.load_checkpoint()  # Recursive call with fresh state
            
            # Ensure new fields exist for backward compatibility
            if 'blog_id' not in checkpoint:
                checkpoint['blog_id'] = checkpoint.get('last_processed_blog_id')
            if 'behavior_id' not in checkpoint:
                checkpoint['behavior_id'] = checkpoint.get('last_processed_behavior_id')
            if 'processed_techniques' not in checkpoint:
                checkpoint['processed_techniques'] = 0
            if 'total_techniques' not in checkpoint:
                checkpoint['total_techniques'] = 0
            
            print(f"✅ Loaded checkpoint: {checkpoint.get('total_blogs_processed', 0)} blogs processed")
            print(f"   Current: Blog {checkpoint.get('blog_id', 'None')}, "
                  f"Behavior {checkpoint.get('behavior_id', 'None')}")
            print(f"   Progress: {checkpoint.get('processed_techniques', 0)}/{checkpoint.get('total_techniques', 0)} techniques")
            return checkpoint
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to load checkpoint, starting fresh: {e}")
            # Return fresh state instead of recursive call to avoid infinite loop
            return {
                'framework': self.framework,
                'blog_id': None,
                'behavior_id': None,
                'last_processed_blog_id': None,
                'last_processed_behavior_id': None,
                'processed_techniques': 0,
                'total_techniques': 0,
                'total_blogs_processed': 0,
                'total_annotations_generated': 0,
                'start_time': datetime.now().isoformat(),
                'last_update': datetime.now().isoformat(),
                'status': 'initialized'
            }
    
    def save_checkpoint(self, blog_id: str = None, behavior_id: int = None, 
                       annotations_count: int = 0, processed_techniques: int = None,
                       total_techniques: int = None, status: str = 'processing'):
        """Save checkpoint state to file"""
        try:
            # Update current position
            if blog_id is not None:
                self.checkpoint_state['blog_id'] = blog_id
                self.checkpoint_state['last_processed_blog_id'] = blog_id
            if behavior_id is not None:
                self.checkpoint_state['behavior_id'] = behavior_id
                self.checkpoint_state['last_processed_behavior_id'] = behavior_id
            
            # Update technique progress
            if processed_techniques is not None:
                self.checkpoint_state['processed_techniques'] = processed_techniques
            if total_techniques is not None:
                self.checkpoint_state['total_techniques'] = total_techniques
            
            # Update other fields
            self.checkpoint_state.update({
                'total_annotations_generated': self.checkpoint_state.get('total_annotations_generated', 0) + annotations_count,
                'last_update': datetime.now().isoformat(),
                'status': status
            })
            
            # Ensure checkpoint directory exists
            self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(self.checkpoint_state, f, indent=2, ensure_ascii=False)
            
            progress_info = ""
            if processed_techniques is not None and total_techniques is not None:
                progress_info = f", Global progress: {processed_techniques}/{total_techniques} techniques"
            
            print(f"💾 Checkpoint saved: Blog {blog_id}, Behavior {behavior_id}{progress_info}, "
                  f"Total annotations: {self.checkpoint_state['total_annotations_generated']}")
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to save checkpoint: {e}")
    
    def load_existing_annotations(self) -> List[Dict[str, Any]]:
        """Load existing annotations from output file"""
        if not file_exists(str(self.output_file)):
            return []
        
        try:
            existing = load_jsonl(str(self.output_file))
            print(f"✅ Loaded {len(existing)} existing annotations from output file")
            return existing
        except Exception as e:
            print(f"⚠️  Warning: Failed to load existing annotations: {e}")
            return []
    
    def should_process_blog(self, blog_entry: Dict) -> bool:
        """Check if blog should be processed based on checkpoint"""
        blog_id = blog_entry.get('blog_id')
        
        # If no checkpoint, process all
        if not self.checkpoint_state.get('last_processed_blog_id'):
            return True
        
        # If this blog was already processed, skip it
        if blog_id == self.checkpoint_state.get('last_processed_blog_id'):
            return False
        
        return True
    
    def should_process_behavior(self, blog_entry: Dict, behavior_id: int) -> bool:
        """Check if behavior should be processed based on checkpoint"""
        blog_id = blog_entry.get('blog_id')
        
        # If no checkpoint, process all
        if not self.checkpoint_state.get('last_processed_blog_id'):
            return True
        
        # If this blog was already processed, check behavior_id
        if blog_id == self.checkpoint_state.get('last_processed_blog_id'):
            return behavior_id > self.checkpoint_state.get('last_processed_behavior_id', -1)
        
        # If this is a new blog, process all behaviors
        return True
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """Get current processing summary"""
        return {
            'framework': self.framework,
            'checkpoint_file': str(self.checkpoint_file),
            'input_file': str(self.input_file),
            'output_file': str(self.output_file),
            'blog_id': self.checkpoint_state.get('blog_id'),
            'behavior_id': self.checkpoint_state.get('behavior_id'),
            'processed_techniques': self.checkpoint_state.get('processed_techniques', 0),
            'total_techniques': self.checkpoint_state.get('total_techniques', 0),
            'total_blogs_processed': self.checkpoint_state.get('total_blogs_processed', 0),
            'total_annotations_generated': self.checkpoint_state.get('total_annotations_generated', 0),
            'last_processed_blog_id': self.checkpoint_state.get('last_processed_blog_id'),
            'last_processed_behavior_id': self.checkpoint_state.get('last_processed_behavior_id'),
            'status': self.checkpoint_state.get('status', 'unknown'),
            'start_time': self.checkpoint_state.get('start_time'),
            'last_update': self.checkpoint_state.get('last_update')
        }
    
    def show_checkpoint_status(self):
        """Display current checkpoint status"""
        print("\n📊 Checkpoint Status:")
        print("=" * 50)
        
        summary = self.get_processing_summary()
        
        print(f"Framework: {summary['framework'].upper()}")
        print(f"Status: {summary['status']}")
        print(f"Total blogs processed: {summary['total_blogs_processed']}")
        print(f"Total annotations generated: {summary['total_annotations_generated']}")
        print(f"Annotations in output file: {self.get_output_file_annotation_count()}")
        print(f"Storage mode: Incremental (each annotation saved immediately)")
        
        if summary['blog_id'] is not None:
            print(f"Current blog: {summary['blog_id']}")
            if summary['behavior_id'] is not None:
                print(f"Current behavior: {summary['behavior_id']}")
        
        if summary['processed_techniques'] > 0 or summary['total_techniques'] > 0:
            print(f"Global technique progress: {summary['processed_techniques']}/{summary['total_techniques']}")
        
        if summary['last_processed_blog_id']:
            print(f"Last processed blog: {summary['last_processed_blog_id']}")
            if summary['last_processed_behavior_id'] is not None:
                print(f"Last processed behavior: {summary['last_processed_behavior_id']}")
        
        if summary['start_time']:
            start_time = datetime.fromisoformat(summary['start_time'])
            print(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if summary['last_update']:
            last_update = datetime.fromisoformat(summary['last_update'])
            print(f"Last update: {last_update.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("=" * 50)
    
    def get_candidates(self, text: str, top_k: int = None) -> List[Dict[str, Any]]:
        """Get candidates for a text using vector similarity search"""
        if top_k is None:
            top_k = VECTOR_TOP_K
        
        # Check if embedding manager is available
        if not self.embedding_manager:
            print("⚠️  Warning: Embedding manager not available, falling back to simple selection")
            return self._fallback_candidate_selection(top_k)
        
        try:
            # Use pre-computed embeddings and FAISS index
            # First get top_k results without threshold to see actual scores
            candidates = self.embedding_manager.find_similar_entries(
                query_text=text,
                framework=self.framework,
                top_k=top_k,
                similarity_threshold=0.0  # Get all top_k results first, filter later
            )
            
            # Debug: Print raw similarity scores
            if candidates:
                print(f"      🔍 Raw similarity scores: {[c.get('similarity', 0) for c in candidates[:5]]}")
            
            # Normalize/enrich candidate fields for downstream usage
            normalized: List[Dict[str, Any]] = []
            for cand in candidates:
                cand_copy = dict(cand)
                if self.framework == "mitre":
                    # Fill name/description from original_entry (title/contents.description)
                    original_entry = cand_copy.get('original_entry', {}) or {}
                    if not cand_copy.get('name'):
                        cand_copy['name'] = original_entry.get('title', '')
                    if not cand_copy.get('description'):
                        desc = ''
                        contents_json = original_entry.get('contents', '{}')
                        try:
                            contents_data = json.loads(contents_json) if isinstance(contents_json, str) else contents_json
                            if isinstance(contents_data, dict):
                                desc = contents_data.get('description', '')
                        except (json.JSONDecodeError, TypeError):
                            pass
                        cand_copy['description'] = desc
                elif self.framework == "capec":
                    # CAPEC: ensure description and name are populated via corpus
                    # Try to find entry by id (numeric) or capec_id (CAPEC-X format)
                    entry = None
                    candidate_id = str(cand_copy.get('id', ''))
                    
                    # Try multiple ID formats
                    if candidate_id in self.corpus:
                        entry = self.corpus[candidate_id]
                    elif candidate_id.replace('CAPEC-', '') in self.corpus:
                        entry = self.corpus[candidate_id.replace('CAPEC-', '')]
                    else:
                        # Try to find by capec_id field
                        for key, val in self.corpus.items():
                            if val.get('capec_id') == candidate_id or val.get('capec_id') == f"CAPEC-{candidate_id}":
                                entry = val
                                break
                    
                    if entry:
                        # Extract CAPEC ID - prefer capec_id field, fallback to id
                        capec_id = entry.get('capec_id', '')
                        if capec_id:
                            # Remove "CAPEC-" prefix to get numeric ID
                            if capec_id.startswith('CAPEC-'):
                                capec_id = capec_id.replace('CAPEC-', '')
                        else:
                            # Use entry id as fallback
                            capec_id = str(entry.get('id', cand_copy.get('id', '')))
                            if capec_id.startswith('CAPEC-'):
                                capec_id = capec_id.replace('CAPEC-', '')
                        
                        cand_copy['id'] = capec_id
                        
                        # Extract CAPEC name from corpus (use title field)
                        if not cand_copy.get('name'):
                            cand_copy['name'] = entry.get('title', '') or entry.get('name', '')
                        
                        # Extract description
                        if not cand_copy.get('description'):
                            description = ""
                            if "_full_content" in entry:
                                description = entry["_full_content"]
                            elif "contents" in entry:
                                try:
                                    contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                                    if isinstance(contents_data, dict):
                                        description = contents_data.get("Description", contents_data.get("Summary", ""))
                                except (json.JSONDecodeError, TypeError):
                                    pass
                            elif "description" in entry:
                                description = entry["description"]
                            cand_copy['description'] = description
                elif self.framework == "cve":
                    # CVE: ensure description and name are populated via corpus
                    entry = self.corpus.get(str(cand_copy.get('id')), {})
                    if entry:
                        if not cand_copy.get('name'):
                            cand_copy['name'] = entry.get('title', entry.get('name', ''))
                        if not cand_copy.get('description'):
                            description = ""
                            if "_full_content" in entry:
                                description = entry["_full_content"]
                            elif "contents" in entry:
                                try:
                                    contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                                    if isinstance(contents_data, dict):
                                        description = contents_data.get("Description", contents_data.get("description", ""))
                                except (json.JSONDecodeError, TypeError):
                                    pass
                            elif "description" in entry:
                                description = entry["description"]
                            cand_copy['description'] = description
                else:  # cwe
                    # CWE: ensure description is populated via corpus if missing
                    if not cand_copy.get('description'):
                        entry = self.corpus.get(str(cand_copy.get('id')), {})
                        cand_copy['description'] = self._extract_cwe_description(entry) if entry else ''
                    if not cand_copy.get('name'):
                        entry = self.corpus.get(str(cand_copy.get('id')), {})
                        cand_copy['name'] = entry.get('title', entry.get('name', '')) if entry else ''
                normalized.append(cand_copy)
            
            return normalized
            
        except Exception as e:
            print(f"⚠️  Warning: Vector similarity search failed, falling back to simple selection: {e}")
            return self._fallback_candidate_selection(top_k)
    
    def _fallback_candidate_selection(self, top_k: int) -> List[Dict[str, Any]]:
        """Fallback to simple selection if embedding fails"""
        candidates = []
        entry_ids = list(self.corpus.keys())[:top_k]
        
        for entry_id in entry_ids:
            entry = self.corpus[entry_id]
            
            if self.framework == "mitre":
                # Parse contents JSON to get description
                contents_json = entry.get('contents', '{}')
                try:
                    contents_data = json.loads(contents_json)
                    description = contents_data.get('description', '')
                except (json.JSONDecodeError, TypeError):
                    description = ''
                
                candidates.append({
                    'id': entry_id,
                    'name': entry.get('title', ''),
                    'description': description,
                    'similarity': 0.5  # Lower similarity for fallback
                })
            elif self.framework == "capec":
                # Extract CAPEC ID - prefer capec_id field, fallback to id
                capec_id = entry.get('capec_id', '')
                if capec_id:
                    # Remove "CAPEC-" prefix to get numeric ID
                    if capec_id.startswith('CAPEC-'):
                        capec_id = capec_id.replace('CAPEC-', '')
                else:
                    # Use entry id as fallback
                    capec_id = str(entry_id)
                    if capec_id.startswith('CAPEC-'):
                        capec_id = capec_id.replace('CAPEC-', '')
                
                # Extract name (use title field)
                name = entry.get('title', '') or entry.get('name', '')
                
                # Extract description
                description = ""
                if "_full_content" in entry:
                    description = entry["_full_content"]
                elif "contents" in entry:
                    try:
                        contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                        if isinstance(contents_data, dict):
                            description = contents_data.get("Description", contents_data.get("Summary", ""))
                    except (json.JSONDecodeError, TypeError):
                        pass
                elif "description" in entry:
                    description = entry["description"]
                
                candidates.append({
                    'id': capec_id,
                    'name': name,
                    'description': description,
                    'similarity': 0.5  # Lower similarity for fallback
                })
            elif self.framework == "cve":
                # Extract CVE name and description
                name = entry.get('title', entry.get('name', ''))
                description = ""
                if "_full_content" in entry:
                    description = entry["_full_content"]
                elif "contents" in entry:
                    try:
                        contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                        if isinstance(contents_data, dict):
                            description = contents_data.get("Description", contents_data.get("description", ""))
                    except (json.JSONDecodeError, TypeError):
                        pass
                elif "description" in entry:
                    description = entry["description"]
                
                candidates.append({
                    'id': entry_id,
                    'name': name,
                    'description': description,
                    'similarity': 0.5  # Lower similarity for fallback
                })
            else:  # cwe
                candidates.append({
                    'id': entry_id,
                    'name': entry.get('name', ''),
                    'description': entry.get('description', ''),
                    'similarity': 0.5  # Lower similarity for fallback
                })
        
        return candidates
    
    def _extract_cwe_description(self, entry: Dict[str, Any]) -> str:
        """Extract CWE description using the same logic as annotate_dataset.py"""
        description = "No description"
        try:
            if "_full_content" in entry:
                description = entry["_full_content"]
            elif "contents" in entry:
                try:
                    contents_data = json.loads(entry["contents"]) if isinstance(entry["contents"], str) else entry["contents"]
                    if isinstance(contents_data, dict):
                        if "Description" in contents_data:
                            description = contents_data["Description"]
                        elif "Summary" in contents_data:
                            description = contents_data["Summary"]
                        elif "@Name" in contents_data:
                            description = contents_data["@Name"]
                except json.JSONDecodeError:
                    pass
            elif "description" in entry:
                description = entry["description"]
        except Exception:
            pass
        return description

    def calculate_total_techniques(self, blog_entries: List[Dict]) -> int:
        """Calculate total number of techniques across all blogs"""
        total_count = 0
        for blog_entry in blog_entries:
            if self.framework == "mitre":
                entries = blog_entry.get('techniques', [])
            elif self.framework == "capec":
                entries = blog_entry.get('capec_entries', [])
            elif self.framework == "cve":
                entries = blog_entry.get('cve_entries', [])
            else:  # cwe
                entries = blog_entry.get('cwe_entries', [])
            total_count += len(entries)
        return total_count

    def _parse_mitre_technique(self, technique_string: str) -> Tuple[str, str]:
        """Parse MITRE technique string to extract technique_id and technique_name.
        
        Examples:
        - "T1562" -> ("T1562", "")
        - "T1203 Exploitation for Client Execution" -> ("T1203", "Exploitation for Client Execution")
        - "T1190 Exploit Public-Facing Application" -> ("T1190", "Exploit Public-Facing Application")
        - "T1562.001" -> ("T1562.001", "")
        """
        if not technique_string or not isinstance(technique_string, str):
            return "", ""
        
        # Use regex to match T followed by numbers, optionally followed by .XXX
        # Pattern: T + digits + optional (. + digits) + optional space + rest as name
        pattern = r'^(T\d+(?:\.\d+)?)\s*(.*)$'
        match = re.match(pattern, technique_string.strip())
        
        if match:
            technique_id = match.group(1).strip()
            technique_name = match.group(2).strip()
            return technique_id, technique_name
        else:
            # Fallback: if no T pattern found, return as is for technique_id
            return technique_string.strip(), ""

    def _decompose_vulnerability(self, vulnerability_text: str) -> List[str]:
        """Decompose vulnerability into atomic behaviors (CWE path)."""
        prompt = f"""You are a cybersecurity expert. Decompose the following query into a list of atomic behaviors (specific, individual actions or conditions).

        Query: "{vulnerability_text}"

        Please identify the key atomic behaviors and return them as a JSON array of strings. Each behavior should be a specific, actionable item.

        Example format:
        ["behavior 1", "behavior 2", "behavior 3"]

        Return only the JSON array:"""
        try:
            response = call_llm_api(
                self.client,
                prompt,
                model=LLM_MODEL,
                max_tokens=2000,
                temperature=LLM_TEMPERATURE,
                call_type="cwe_mapping"
            )
            if not response:
                return [vulnerability_text]
            import re
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                try:
                    items = json.loads(json_match.group())
                    cleaned = [s.strip() for s in items if isinstance(s, str) and s.strip()]
                    return cleaned or [vulnerability_text]
                except json.JSONDecodeError:
                    return [vulnerability_text]
            return [vulnerability_text]
        except Exception:
            return [vulnerability_text]

    def _llm_judge_cwe_mapping(self, full_vulnerability: str, atomic_behavior: str, candidates: List[Dict[str, Any]], blog_id: int, behavior_id: int) -> List[Dict[str, Any]]:
        """LLM selects exactly one CWE candidate for an atomic behavior, aligned with annotate_dataset.py."""
        print(f"🤖 Using LLM to judge CWE mapping for atomic behavior: {atomic_behavior[:80]}...")
        
        if not candidates:
            return []
        
        # Prepare the prompt for LLM
        prompt = f"""You are a cybersecurity expert. Please analyze whether the following atomic behavior from a vulnerability description has a mapping relationship with the given CWE entries.

Vulnerability Description: "{full_vulnerability}"

Atomic Behavior: "{atomic_behavior}"

CWE Candidates (with similarity scores):
"""
        
        for i, candidate in enumerate(candidates, 1):
            prompt += f"""
{i}. CWE-{candidate['id']}: {candidate.get('name', 'Unknown')}
   Description: {candidate.get('description', 'No description')}
   Similarity Score: {candidate.get('similarity', 0):.3f}
"""
        
        prompt += f"""

Please analyze each CWE candidate and determine if it has a mapping relationship with the atomic behavior. Consider:
1. Semantic similarity between the atomic behavior and CWE description
2. Whether the CWE describes the same type of weakness/vulnerability
3. The similarity score (higher scores indicate better matches)

IMPORTANT: You can only select ONE CWE candidate that best matches the atomic behavior. If multiple candidates are suitable, choose the one with the highest similarity score.

For each CWE candidate, respond with:
- "YES" if it is the BEST match for the atomic behavior (only one should be YES)
- "NO" for all other candidates

Format your response as a JSON array with the same number of elements as CWE candidates:
["YES", "NO", "NO", ...]

Return only the JSON array:"""

        try:
            # Call LLM for judgment
            response = call_llm_api(
                self.client,
                prompt,
                model=LLM_MODEL,
                max_tokens=2000,
                temperature=LLM_TEMPERATURE,
                call_type="cwe_mapping"
            )
            
            result = response.strip() if response else ""
            print(f"🔍 Raw LLM response: {repr(result)}")
            
            # Check if response is empty
            if not result:
                print("⚠️  LLM returned empty response, returning best candidate based on similarity")
                # Return the candidate with highest similarity score
                best_candidate = max(candidates, key=lambda x: x.get('similarity', 0))
                return [best_candidate]
            
            # Parse the response
            import re
            json_match = re.search(r'\[.*?\]', result, re.DOTALL)
            if json_match:
                try:
                    judgments = json.loads(json_match.group())
                    if isinstance(judgments, list) and len(judgments) == len(candidates):
                        # Filter candidates based on LLM judgment
                        mapped_candidates = []
                        for i, (candidate, judgment) in enumerate(zip(candidates, judgments)):
                            if judgment.upper() == "YES":
                                mapped_candidates.append(candidate)
                                print(f"  ✅ LLM approved CWE-{candidate['id']}: {candidate.get('name', 'Unknown')}")
                            else:
                                print(f"  ❌ LLM rejected CWE-{candidate['id']}: {candidate.get('name', 'Unknown')}")
                        
                        # Ensure only one candidate is selected
                        if len(mapped_candidates) > 1:
                            print(f"⚠️  LLM selected {len(mapped_candidates)} candidates, keeping only the one with highest similarity")
                            best_candidate = max(mapped_candidates, key=lambda x: x.get('similarity', 0))
                            mapped_candidates = [best_candidate]
                        elif len(mapped_candidates) == 0:
                            print("⚠️  LLM rejected all candidates, skipping this atomic behavior")
                            return []
                        
                        return mapped_candidates
                except json.JSONDecodeError as e:
                    print(f"⚠️  JSON decode error: {e}")
            
            # Fallback: if LLM response parsing fails, skip this atomic behavior
            print("⚠️  LLM response parsing failed, skipping this atomic behavior")
            return []
            
        except Exception as e:
            print(f"❌ Error calling LLM: {e}")
            # Fallback: skip this atomic behavior due to error
            return []

    def _select_best_cwe_with_llm(self, cwe_candidates: List[Dict[str, Any]], vulnerability: str) -> Dict[str, Any]:
        """Pick best CWE among multiple for the same behavior using LLM; fallback to highest similarity."""
        if not cwe_candidates:
            return {}
        prompt = f"""You are a cybersecurity expert. Select which CWE best matches the COMPLETE vulnerability description below.

Vulnerability Description: "{vulnerability}"

CWE Candidates to compare:
"""
        for idx, c in enumerate(cwe_candidates, 1):
            prompt += f"\n{idx}. CWE-{c['id']}: {c.get('name','Unknown')}\n   Description: {c.get('description','No description')}\n   Similarity Score: {c.get('similarity',0):.3f}\n   Atomic Behavior: {c.get('atomic_behavior','N/A')}\n"
        prompt += f"""

Respond as a JSON array with exactly {len(cwe_candidates)} elements in order where only the best candidate is "YES": ["YES", "NO", ...]. Return only the JSON array."""
        try:
            response = call_llm_api(
                self.client,
                prompt,
                model=LLM_MODEL,
                max_tokens=1200,
                temperature=LLM_TEMPERATURE,
                call_type="cwe_judgment"
            )
            if not response:
                return max(cwe_candidates, key=lambda x: x.get('similarity', 0))
            import re
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                try:
                    judgments = json.loads(json_match.group())
                    if isinstance(judgments, list) and len(judgments) == len(cwe_candidates):
                        for cand, j in zip(cwe_candidates, judgments):
                            if isinstance(j, str) and j.strip().upper() == "YES":
                                return cand
                        return max(cwe_candidates, key=lambda x: x.get('similarity', 0))
                except json.JSONDecodeError:
                    return max(cwe_candidates, key=lambda x: x.get('similarity', 0))
            return max(cwe_candidates, key=lambda x: x.get('similarity', 0))
        except Exception:
            return max(cwe_candidates, key=lambda x: x.get('similarity', 0))

    def _filter_best_cwe_per_behavior(self, all_mapped_cwes: List[Dict[str, Any]], vulnerability: str, blog_id: int, behavior_id: int) -> List[Dict[str, Any]]:
        """Group by (blog_id, behavior_id) and keep the single best CWE using LLM selection."""
        if not all_mapped_cwes:
            return []
        grouped: Dict[tuple, List[Dict[str, Any]]] = {}
        for c in all_mapped_cwes:
            key = (c.get('blog_id', blog_id), c.get('behavior_id', behavior_id))
            grouped.setdefault(key, []).append(c)
        filtered: List[Dict[str, Any]] = []
        for (_b, _beh), cwes in grouped.items():
            if len(cwes) == 1:
                filtered.append(cwes[0])
            else:
                best = self._select_best_cwe_with_llm(cwes, vulnerability)
                if best:
                    filtered.append(best)
        return filtered
    
    def llm_judge_match(self, text: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to judge if candidate matches the text"""
        if self.framework == "mitre":
            # Prefer official technique ID (e.g., T1562) from candidate.original_entry.contents.external_id; fallback to corpus by candidate['id']
            mitre_technique_raw = ""
            try:
                original_entry = candidate.get('original_entry', {}) or {}
                contents_json = original_entry.get('contents')
                if contents_json is not None:
                    try:
                        contents_data = json.loads(contents_json) if isinstance(contents_json, str) else contents_json
                        if isinstance(contents_data, dict):
                            mitre_technique_raw = contents_data.get('external_id') or contents_data.get('technique_id') or ""
                    except (json.JSONDecodeError, TypeError):
                        pass
                if not mitre_technique_raw:
                    corpus_entry = self.corpus.get(str(candidate.get('id'))) or self.corpus.get(candidate.get('id'))
                    if corpus_entry:
                        mitre_technique_raw = corpus_entry.get('mitre_id', '')
                        # cjson = corpus_entry.get('contents')
                        # try:
                        #     cdata = json.loads(cjson) if isinstance(cjson, str) else cjson
                        #     if isinstance(cdata, dict):
                        #         mitre_technique_raw = cdata.get('external_id') or cdata.get('technique_id') or ""
                        # except (json.JSONDecodeError, TypeError):
                        #     pass
            except Exception:
                pass
            
            # Parse the technique string to extract ID and name
            mitre_technique_id, mitre_technique_name = self._parse_mitre_technique(mitre_technique_raw)
            if not mitre_technique_name:
                mitre_technique_name = candidate['name']
            prompt = f"""Analyze if the following MITRE ATT&CK technique matches the attack behavior description:

MITRE Technique:
- ID: {mitre_technique_id or candidate['id']}
- Name: {candidate['name']}
- Description: {candidate['description']}

Attack Behavior Description:
{text}

Please provide your judgment in the following format:
MATCH: YES/NO
REASONING: [Brief explanation of why it matches or doesn't match]
CONFIDENCE: HIGH/MEDIUM/LOW
"""
        else:  # cwe
            prompt = f"""Analyze if the following CWE entry matches the vulnerability description:

CWE Entry:
- ID: {candidate['id']}
- Name: {candidate['name']}
- Description: {candidate['description']}

Vulnerability Description:
{text}

Please provide your judgment in the following format:
MATCH: YES/NO
REASONING: [Brief explanation of why it matches or doesn't match]
CONFIDENCE: HIGH/MEDIUM/LOW
"""
        
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="capec_batch_judgment"
        )
        
        if not response:
            return {'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'}
        
        # Parse the response
        result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('match'):
                result['match'] = 'yes' in line.lower()
            elif line.lower().startswith('reasoning'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['reasoning'] = parts[1].strip()
            elif line.lower().startswith('confidence'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['confidence'] = parts[1].strip()
        
        return result, mitre_technique_id, mitre_technique_name
    
    def llm_judge_match_batch(self, text: str, candidates: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], str, str]]:
        """OPTIMIZED: Batch LLM judgment for multiple candidates at once"""
        if not candidates:
            return []
        
        if self.framework == "mitre":
            # Build batch prompt for MITRE
            candidates_text = ""
            mitre_info_list = []
            
            for i, candidate in enumerate(candidates, 1):
                # Extract MITRE technique ID and name
                mitre_technique_raw = ""
                try:
                    original_entry = candidate.get('original_entry', {}) or {}
                    contents_json = original_entry.get('contents')
                    if contents_json is not None:
                        try:
                            contents_data = json.loads(contents_json) if isinstance(contents_json, str) else contents_json
                            if isinstance(contents_data, dict):
                                mitre_technique_raw = contents_data.get('external_id') or contents_data.get('technique_id') or ""
                        except (json.JSONDecodeError, TypeError):
                            pass
                    if not mitre_technique_raw:
                        corpus_entry = self.corpus.get(str(candidate.get('id'))) or self.corpus.get(candidate.get('id'))
                        if corpus_entry:
                            mitre_technique_raw = corpus_entry.get('mitre_id', '')
                except Exception:
                    pass
                
                mitre_technique_id, mitre_technique_name = self._parse_mitre_technique(mitre_technique_raw)
                if not mitre_technique_name:
                    mitre_technique_name = candidate['name']
                if not mitre_technique_id:
                    mitre_technique_id = candidate['id']
                
                mitre_info_list.append((mitre_technique_id, mitre_technique_name))
                
                # Truncate description to save tokens
                desc = candidate.get('description', '')[:200] if candidate.get('description') else 'No description'
                candidates_text += f"""
{i}. {mitre_technique_id}: {candidate['name']}
   Description: {desc}
"""
            
            prompt = f"""Analyze which MITRE ATT&CK technique(s) match the attack behavior description. You can select multiple or none.

Attack Behavior Description:
{text}

MITRE Techniques:
{candidates_text}

For each technique, provide judgment in this format:
<ID>: MATCH: YES/NO | REASONING: <brief> | CONFIDENCE: HIGH/MEDIUM/LOW

Provide judgments for all techniques."""
        else:  # cwe
            # Build batch prompt for CWE
            candidates_text = ""
            for i, candidate in enumerate(candidates, 1):
                desc = candidate.get('description', '')[:200] if candidate.get('description') else 'No description'
                candidates_text += f"""
{i}. CWE-{candidate['id']}: {candidate.get('name', 'Unknown')}
   Description: {desc}
"""
            
            prompt = f"""Analyze which CWE entry(ies) match the vulnerability description. You can select multiple or none.

Vulnerability Description:
{text}

CWE Candidates:
{candidates_text}

For each candidate, provide judgment in this format:
CWE-<ID>: MATCH: YES/NO | REASONING: <brief> | CONFIDENCE: HIGH/MEDIUM/LOW

Provide judgments for all candidates."""
        
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="mitre_batch_judgment" if self.framework == "mitre" else "cwe_batch_judgment"
        )
        
        if not response:
            if self.framework == "mitre":
                return [({'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'}, mitre_info_list[i][0], mitre_info_list[i][1]) 
                        for i in range(len(candidates))]
            else:
                return [({'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'}, '', '') 
                        for _ in candidates]
        
        # Parse batch response
        results = []
        for i, candidate in enumerate(candidates):
            result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
            
            if self.framework == "mitre":
                mitre_technique_id, mitre_technique_name = mitre_info_list[i]
                search_id = mitre_technique_id
            else:
                search_id = f"CWE-{candidate['id']}"
                mitre_technique_id, mitre_technique_name = '', ''
            
            # Find judgment for this candidate in response
            lines = response.split('\n')
            for line in lines:
                if search_id.upper() in line.upper():
                    line_lower = line.lower()
                    if 'match:' in line_lower:
                        result['match'] = 'yes' in line_lower.split('match:')[1].split('|')[0]
                    if 'reasoning:' in line_lower:
                        parts = line_lower.split('reasoning:')
                        if len(parts) > 1:
                            reasoning_part = parts[1].split('|')[0].strip()
                            result['reasoning'] = reasoning_part
                    if 'confidence:' in line_lower:
                        parts = line_lower.split('confidence:')
                        if len(parts) > 1:
                            conf_part = parts[1].strip().split()[0].upper()
                            if conf_part in ['HIGH', 'MEDIUM', 'LOW']:
                                result['confidence'] = conf_part
            
            results.append((result, mitre_technique_id, mitre_technique_name))
        
        return results
    
    def decompose_attack_behavior(self, behavior_text: str) -> List[str]:
        """Decompose complex attack behavior into atomic behaviors for MITRE framework"""
        if self.framework != "mitre":
            return [behavior_text]  # For CWE, return original text
        
        print(f"    🧠 Decomposing attack behavior into atomic behaviors...")
        
        # Prepare prompt for LLM decomposition
        prompt = f"""You are a cybersecurity expert. Decompose the following query into a list of atomic behaviors (specific, individual actions or conditions).

Query: "{behavior_text}"

Please identify the key atomic behaviors and return them as a JSON array of strings. Each behavior should be a specific, actionable item.

Example format:
["behavior 1", "behavior 2", "behavior 3"]

Return only the JSON array:"""
        try:
            # Call LLM for decomposition
            print(f"      🤖 Calling LLM for behavior decomposition...")
            response = call_llm_api(
                self.client,
                prompt,
                model=LLM_MODEL,
                max_tokens=MAX_OUTPUT_TOKENS,
                call_type="decomposition"
            )
            
            print(f"      🔍 LLM response: {repr(response)}")
            
            if not response:
                print(f"      ⚠️  LLM decomposition failed (no response), using original behavior")
                return [behavior_text]
            
            # Parse the response
            import re
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                try:
                    atomic_behaviors = json.loads(json_match.group())
                    if isinstance(atomic_behaviors, list) and len(atomic_behaviors) > 0:
                        # Clean up the atomic behaviors
                        cleaned_behaviors = []
                        for behavior in atomic_behaviors:
                            if isinstance(behavior, str) and behavior.strip():
                                cleaned_behaviors.append(behavior.strip())
                        
                        if cleaned_behaviors:
                            print(f"      ✅ Decomposed into {len(cleaned_behaviors)} atomic behaviors")
                            return cleaned_behaviors
                        else:
                            print(f"      ⚠️  No valid behaviors found after cleaning")
                except json.JSONDecodeError as e:
                    print(f"      ⚠️  JSON parsing error in decomposition: {e}")
                    print(f"      📝 Raw response: {response}")
            else:
                print(f"      ⚠️  No JSON array found in response")
                print(f"      📝 Raw response: {response}")
            
            # Fallback to original behavior
            print(f"      ⚠️  Decomposition parsing failed, using original behavior")
            return [behavior_text]
            
        except Exception as e:
            print(f"      ⚠️  Error during behavior decomposition: {e}")
            import traceback
            traceback.print_exc()
            return [behavior_text]
    
    def process_mitre_behavior_with_decomposition(self, behavior_text: str, blog_id: int, behavior_id: int) -> List[Dict[str, Any]]:
        """Process MITRE behavior with atomic decomposition and RAG strategy (OPTIMIZED)"""
        print(f"    🔍 Processing MITRE behavior with decomposition+RAG strategy...")
        
        # Step 1: Decompose into atomic behaviors
        atomic_behaviors = self.decompose_attack_behavior(behavior_text)
        
        # Step 2: RAG matching for each atomic behavior
        all_matches = []
        
        for behavior_idx, atomic_behavior in enumerate(atomic_behaviors, 1):
            print(f"      📋 Processing atomic behavior {behavior_idx}/{len(atomic_behaviors)}: {atomic_behavior[:80]}...")
            
            # Get candidates for this atomic behavior
            candidates = self.get_candidates(atomic_behavior)
            
            if not candidates:
                print(f"        ⚠️  No candidates found for atomic behavior {behavior_idx}")
                continue
            
            # OPTIMIZATION: Filter candidates by similarity threshold and limit to top 5
            # Use lower threshold (0.5) if embedding manager is not available (fallback mode)
            similarity_threshold = 0.5 if not self.embedding_manager else 0.6
            filtered_candidates = [
                c for c in candidates 
                if c.get('similarity', 0) >= similarity_threshold
            ][:5]  # Limit to top 5 candidates
            
            if not filtered_candidates:
                print(f"        ⚠️  No candidates above similarity threshold ({similarity_threshold})")
                continue
            
            # OPTIMIZATION: Skip LLM for very high similarity matches (>0.85)
            best_match = None
            best_score = 0
            
            # Check for high-similarity direct match first
            high_sim_candidates = [c for c in filtered_candidates if c.get('similarity', 0) > 0.85]
            if high_sim_candidates:
                # Use highest similarity candidate directly without LLM call
                best_candidate = max(high_sim_candidates, key=lambda x: x.get('similarity', 0))
                # Extract MITRE info
                mitre_technique_raw = ""
                try:
                    original_entry = best_candidate.get('original_entry', {}) or {}
                    contents_json = original_entry.get('contents')
                    if contents_json is not None:
                        try:
                            contents_data = json.loads(contents_json) if isinstance(contents_json, str) else contents_json
                            if isinstance(contents_data, dict):
                                mitre_technique_raw = contents_data.get('external_id') or contents_data.get('technique_id') or ""
                        except (json.JSONDecodeError, TypeError):
                            pass
                    if not mitre_technique_raw:
                        corpus_entry = self.corpus.get(str(best_candidate.get('id'))) or self.corpus.get(best_candidate.get('id'))
                        if corpus_entry:
                            mitre_technique_raw = corpus_entry.get('mitre_id', '')
                except Exception:
                    pass
                mitre_technique_id, mitre_technique_name = self._parse_mitre_technique(mitre_technique_raw)
                if not mitre_technique_name:
                    mitre_technique_name = best_candidate['name']
                if not mitre_technique_id:
                    mitre_technique_id = best_candidate['id']
                
                best_match = {
                    'id': best_candidate['id'],
                    'technique_id': mitre_technique_id,
                    'technique_name': mitre_technique_name,
                    'name': best_candidate['name'],
                    'similarity': best_candidate['similarity'],
                    'llm_judgment': f"High similarity match (score: {best_candidate['similarity']:.2f})",
                    'confidence': 'HIGH',
                    'atomic_behavior': atomic_behavior,
                    'behavior_index': behavior_idx
                }
                print(f"        ⚡ High similarity match ({best_candidate['similarity']:.2f}), skipping LLM call")
            else:
                # OPTIMIZATION: Batch LLM judgment for all candidates at once
                judgments = self.llm_judge_match_batch(atomic_behavior, filtered_candidates)
                
                # Find best match from batch results
                for candidate, (judgment, mitre_technique_id, mitre_technique_name) in zip(filtered_candidates, judgments):
                    if judgment['match']:
                        # Calculate a simple score based on confidence
                        confidence_score = {'LOW': 0.3, 'MEDIUM': 0.6, 'HIGH': 0.9}.get(
                            judgment['confidence'], 0.5
                        )
                        
                        if confidence_score > best_score:
                            best_score = confidence_score
                            best_match = {
                                'id': candidate['id'],
                                'technique_id': mitre_technique_id,
                                'technique_name': mitre_technique_name,
                                'name': candidate['name'],
                                'similarity': candidate['similarity'],
                                'llm_judgment': judgment['reasoning'],
                                'confidence': judgment['confidence'],
                                'atomic_behavior': atomic_behavior,
                                'behavior_index': behavior_idx
                            }
            
            if best_match:
                all_matches.append(best_match)
                print(f"        ✅ Matched to {best_match['technique_id']} (confidence: {best_match['confidence']})")
            else:
                print(f"        ⚠️  No good match found for atomic behavior {behavior_idx}")
        
        return all_matches
    
    def process_capec_pattern_with_decomposition(self, pattern_text: str, blog_id: int, behavior_id: int) -> List[Dict[str, Any]]:
        """Process CAPEC attack pattern with direct LLM judgment (no decomposition)"""
        print(f"    🔍 Processing CAPEC pattern with direct LLM judgment...")
        print(f"    📝 Pattern text: {pattern_text[:100]}..." if len(pattern_text) > 100 else f"    📝 Pattern text: {pattern_text}")
        
        # Get candidates for the original pattern text (no decomposition)
        print(f"    🔎 Step 1: Vector similarity search for candidates...")
        candidates = self.get_candidates(pattern_text)
        
        if not candidates:
            print(f"    ⚠️  No CAPEC candidates found")
            return []
        
        print(f"    📊 Found {len(candidates)} candidates from vector search")
        
        # OPTIMIZATION: Filter candidates by similarity threshold and limit to top 5
        # Use lower threshold (0.5) if embedding manager is not available (fallback mode)
        similarity_threshold = 0.5 if not self.embedding_manager else 0.6
        filtered_candidates = [
            c for c in candidates 
            if c.get('similarity', 0) >= similarity_threshold
        ][:5]  # Limit to top 5 candidates
        
        if not filtered_candidates:
            print(f"    ⚠️  No candidates above similarity threshold ({similarity_threshold})")
            return []
        
        print(f"    📋 Step 2: Filtered to {len(filtered_candidates)} candidates above threshold {similarity_threshold}")
        for i, cand in enumerate(filtered_candidates, 1):
            print(f"      {i}. CAPEC-{cand['id']}: {cand.get('name', 'Unknown')[:50]} (similarity: {cand.get('similarity', 0):.3f})")
        
        # Use LLM to judge all candidates and collect matches
        matches = []
        
        # OPTIMIZATION: Skip LLM for very high similarity matches (>0.85)
        high_sim_candidates = [c for c in filtered_candidates if c.get('similarity', 0) > 0.85]
        if high_sim_candidates:
            print(f"    ⚡ Step 3: Found {len(high_sim_candidates)} high-similarity candidates (>0.85), skipping LLM call")
            # Use high similarity candidates directly without LLM call
            for candidate in high_sim_candidates:
                match = {
                    'id': candidate['id'],
                    'capec_id': f"CAPEC-{candidate['id']}",
                    'capec_name': candidate['name'],
                    'similarity': candidate['similarity'],
                    'llm_judgment': f"High similarity match (score: {candidate['similarity']:.2f})",
                    'confidence': 'HIGH'
                }
                matches.append(match)
                print(f"      ✅ High similarity match: {match['capec_id']} ({candidate['similarity']:.2f})")
        
        # For lower similarity candidates, use LLM judgment
        lower_sim_candidates = [c for c in filtered_candidates if c.get('similarity', 0) <= 0.85]
        if lower_sim_candidates:
            print(f"    🤖 Step 4: Calling LLM to judge {len(lower_sim_candidates)} candidates...")
            # OPTIMIZATION: Batch LLM judgment
            judgments = self.llm_judge_capec_match_batch(pattern_text, lower_sim_candidates)
            
            print(f"    📊 Step 5: LLM returned judgments, parsing results...")
            # Collect matches based on LLM judgment
            for candidate, judgment in zip(lower_sim_candidates, judgments):
                if judgment['match']:
                    match = {
                        'id': candidate['id'],
                        'capec_id': f"CAPEC-{candidate['id']}",
                        'capec_name': candidate['name'],
                        'similarity': candidate['similarity'],
                        'llm_judgment': judgment['reasoning'],
                        'confidence': judgment['confidence']
                    }
                    matches.append(match)
                    print(f"      ✅ LLM matched: {match['capec_id']} (confidence: {match['confidence']})")
                else:
                    print(f"      ❌ LLM rejected: CAPEC-{candidate['id']} (confidence: {judgment.get('confidence', 'LOW')})")
        
        if not matches:
            print(f"    ⚠️  No CAPEC matches found after LLM judgment")
        else:
            print(f"    ✅ Final result: {len(matches)} match(es) found")
        
        return matches
    
    def process_cve_exploit_direct(self, exploit_text: str, blog_id: int, behavior_id: int, cve_id: str = None) -> List[Dict[str, Any]]:
        """Process CVE exploit context with direct CVE ID matching (no vector search)"""
        print(f"    🔍 Processing CVE with direct ID matching...")
        print(f"    📝 Exploit text: {exploit_text[:150]}..." if len(exploit_text) > 150 else f"    📝 Exploit text: {exploit_text}")
        
        matches = []
        
        # Method 1: Use provided cve_id from entry
        if cve_id:
            print(f"    🎯 Using provided CVE ID: {cve_id}")
            # Try both with and without CVE- prefix
            cve_entry = self.corpus.get(cve_id, None) or self.corpus.get(cve_id.replace('CVE-', ''), None)
            if cve_entry:
                # Extract description from CVE entry
                description = ""
                try:
                    if isinstance(cve_entry.get('contents'), str):
                        contents = json.loads(cve_entry.get('contents', '{}'))
                        descriptions = contents.get('descriptions', [])
                        if descriptions and len(descriptions) > 0:
                            description = descriptions[0].get('value', '')
                except:
                    pass
                
                if not description:
                    description = cve_entry.get('title', '')
                
                match = {
                    'id': cve_entry.get('id', cve_id.replace('CVE-', '')),
                    'cve_id': cve_id if cve_id.startswith('CVE-') else f"CVE-{cve_id}",
                    'cve_description': description,
                    'similarity': 1.0,  # Direct match, perfect similarity
                    'llm_judgment': f"Direct CVE ID match from entry",
                    'confidence': 'HIGH'
                }
                matches.append(match)
                print(f"    ✅ Direct match found: {match['cve_id']}")
                return matches
            else:
                print(f"    ⚠️  CVE ID {cve_id} not found in corpus")
        
        # Method 2: Extract CVE ID from exploit text using regex
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        found_cve_ids = re.findall(cve_pattern, exploit_text, re.IGNORECASE)
        
        if found_cve_ids:
            print(f"    🔍 Found CVE IDs in text: {found_cve_ids}")
            for found_cve_id in found_cve_ids:
                # Try both with and without CVE- prefix
                cve_entry = self.corpus.get(found_cve_id.upper(), None) or self.corpus.get(found_cve_id.upper().replace('CVE-', ''), None)
                if cve_entry:
                    # Extract description from CVE entry
                    description = ""
                    try:
                        if isinstance(cve_entry.get('contents'), str):
                            contents = json.loads(cve_entry.get('contents', '{}'))
                            descriptions = contents.get('descriptions', [])
                            if descriptions and len(descriptions) > 0:
                                description = descriptions[0].get('value', '')
                    except:
                        pass
                    
                    if not description:
                        description = cve_entry.get('title', '')
                    
                    match = {
                        'id': cve_entry.get('id', cve_id_clean),
                        'cve_id': found_cve_id.upper(),
                        'cve_description': description,
                        'similarity': 1.0,  # Direct match from text
                        'llm_judgment': f"CVE ID extracted from exploit text",
                        'confidence': 'HIGH'
                    }
                    matches.append(match)
                    print(f"    ✅ Matched CVE from text: {match['cve_id']}")
                else:
                    print(f"    ⚠️  CVE ID {found_cve_id} not found in corpus")
        
        if not matches:
            print(f"    ⚠️  No CVE matches found (no CVE ID provided or found in text)")
        
        return matches
    
    def llm_judge_capec_match(self, pattern_text: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to judge if CAPEC candidate matches the attack pattern"""
        prompt = f"""Analyze if the following CAPEC attack pattern matches the described behavior:

CAPEC Entry:
- ID: CAPEC-{candidate['id']}
- Name: {candidate['name']}
- Description: {candidate['description']}

Attack Pattern Description:
{pattern_text}

Please provide your judgment in the following format:
MATCH: YES/NO
REASONING: [Brief explanation of why it matches or doesn't match]
CONFIDENCE: HIGH/MEDIUM/LOW
"""
        
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="capec_batch_judgment"
        )
        
        if not response:
            return {'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'}
        
        # Parse the response
        result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('match'):
                result['match'] = 'yes' in line.lower()
            elif line.lower().startswith('reasoning'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['reasoning'] = parts[1].strip()
            elif line.lower().startswith('confidence'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['confidence'] = parts[1].strip()
        
        return result
    
    def llm_judge_capec_match_batch(self, pattern_text: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """OPTIMIZED: Batch LLM judgment for multiple CAPEC candidates at once"""
        if not candidates:
            return []
        
        print(f"      📤 Preparing LLM prompt for {len(candidates)} candidates...")
        
        # Build batch prompt (optimized: shorter descriptions)
        candidates_text = ""
        for i, candidate in enumerate(candidates, 1):
            # Truncate description to save tokens (reduced to 100 chars)
            desc = candidate.get('description', '')[:100] if candidate.get('description') else ''
            name = candidate.get('name', 'Unknown')[:50]  # Truncate name too
            candidates_text += f"{i}. CAPEC-{candidate['id']}: {name}"
            if desc:
                candidates_text += f" - {desc}"
            candidates_text += "\n"
        
        # Truncate pattern text to save tokens
        pattern_short = pattern_text[:300] if len(pattern_text) > 300 else pattern_text
        
        prompt = f"""Which CAPEC pattern(s) match this behavior? Select multiple or none.

Behavior: {pattern_short}

Candidates:
{candidates_text}

Format: CAPEC-<ID>: MATCH: YES/NO | CONFIDENCE: HIGH/MEDIUM/LOW
Provide judgments for all candidates."""
        
        print(f"      🤖 Calling LLM API (model: {LLM_MODEL})...")
        print(f"      ⏳ Waiting for LLM response...")
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="capec_batch_judgment"
        )
        print(f"      ✅ LLM API call completed")
        
        if not response:
            return [{'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'} for _ in candidates]
        
        # Debug: Print LLM response for troubleshooting
        print(f"      🔍 LLM response: {repr(response[:500])}...")  # Print first 500 chars
        
        # Parse batch response
        results = []
        for candidate in candidates:
            capec_id = f"CAPEC-{candidate['id']}"
            result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
            
            # Find judgment for this candidate in response
            lines = response.split('\n')
            found_line = None
            for line in lines:
                # More flexible matching: check for CAPEC ID in various formats
                line_upper = line.upper()
                line_lower = line.lower()
                # Try exact match first
                if capec_id.upper() in line_upper:
                    found_line = line
                    break
                # Try without CAPEC- prefix
                elif f"-{candidate['id']}" in line_upper or candidate['id'] in line_upper:
                    # Make sure it's actually a CAPEC reference
                    if 'capec' in line_lower or 'CAPEC' in line:
                        found_line = line
                        break
            
            if found_line:
                line_lower = found_line.lower()
                if 'match:' in line_lower:
                    match_part = line_lower.split('match:')[1].split('|')[0]
                    result['match'] = 'yes' in match_part
                    print(f"      📋 Parsed match for {capec_id}: {result['match']} (from: {match_part.strip()})")
                if 'reasoning:' in line_lower:
                    parts = line_lower.split('reasoning:')
                    if len(parts) > 1:
                        reasoning_part = parts[1].split('|')[0].strip()
                        result['reasoning'] = reasoning_part
                if 'confidence:' in line_lower:
                    parts = line_lower.split('confidence:')
                    if len(parts) > 1:
                        conf_part = parts[1].strip().split()[0].upper()
                        if conf_part in ['HIGH', 'MEDIUM', 'LOW']:
                            result['confidence'] = conf_part
            else:
                print(f"      ⚠️  Could not find judgment line for {capec_id} in LLM response")
            
            results.append(result)
        
        return results
    
    def llm_judge_cve_match(self, exploit_text: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to judge if CVE candidate matches the exploit context"""
        cve_id = candidate['id'] if candidate['id'].startswith('CVE-') else f"CVE-{candidate['id']}"
        
        prompt = f"""Analyze if the following CVE vulnerability is mentioned or exploited in the security incident:

CVE Entry:
- ID: {cve_id}
- Description: {candidate.get('description', 'No description')}

Security Incident/Exploit Context:
{exploit_text}

Please provide your judgment in the following format:
MATCH: YES/NO
REASONING: [Brief explanation of why it matches or doesn't match]
CONFIDENCE: HIGH/MEDIUM/LOW

Note: Only mark as YES if the CVE is explicitly mentioned or the vulnerability is clearly being exploited.
"""
        
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="capec_batch_judgment"
        )
        
        if not response:
            return {'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'}
        
        # Parse the response
        result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('match'):
                result['match'] = 'yes' in line.lower()
            elif line.lower().startswith('reasoning'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['reasoning'] = parts[1].strip()
            elif line.lower().startswith('confidence'):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result['confidence'] = parts[1].strip()
        
        return result
    
    def llm_judge_cve_match_batch(self, exploit_text: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """OPTIMIZED: Batch LLM judgment for multiple CVE candidates at once"""
        if not candidates:
            return []
        
        # Build batch prompt
        candidates_text = ""
        for i, candidate in enumerate(candidates, 1):
            cve_id = candidate['id'] if candidate['id'].startswith('CVE-') else f"CVE-{candidate['id']}"
            desc = candidate.get('description', '')[:200] if candidate.get('description') else 'No description'
            candidates_text += f"""
{i}. {cve_id}: {desc}
"""
        
        prompt = f"""Analyze which CVE vulnerability(ies) are mentioned or exploited in the security incident. You can select multiple or none.

Security Incident/Exploit Context:
{exploit_text}

CVE Candidates:
{candidates_text}

For each candidate, provide judgment in this format:
CVE-<ID>: MATCH: YES/NO | REASONING: <brief> | CONFIDENCE: HIGH/MEDIUM/LOW

Note: Only mark as YES if the CVE is explicitly mentioned or the vulnerability is clearly being exploited.
Provide judgments for all candidates."""
        
        response = call_llm_api(
            self.client,
            prompt,
            model=LLM_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=LLM_TEMPERATURE,
            call_type="cve_batch_judgment"
        )
        
        if not response:
            return [{'match': False, 'reasoning': 'No LLM response', 'confidence': 'LOW'} for _ in candidates]
        
        # Parse batch response
        results = []
        for candidate in candidates:
            cve_id = candidate['id'] if candidate['id'].startswith('CVE-') else f"CVE-{candidate['id']}"
            result = {'match': False, 'reasoning': '', 'confidence': 'LOW'}
            
            # Find judgment for this candidate in response
            lines = response.split('\n')
            for line in lines:
                if cve_id.upper() in line.upper():
                    line_lower = line.lower()
                    if 'match:' in line_lower:
                        result['match'] = 'yes' in line_lower.split('match:')[1].split('|')[0]
                    if 'reasoning:' in line_lower:
                        parts = line_lower.split('reasoning:')
                        if len(parts) > 1:
                            reasoning_part = parts[1].split('|')[0].strip()
                            result['reasoning'] = reasoning_part
                    if 'confidence:' in line_lower:
                        parts = line_lower.split('confidence:')
                        if len(parts) > 1:
                            conf_part = parts[1].strip().split()[0].upper()
                            if conf_part in ['HIGH', 'MEDIUM', 'LOW']:
                                result['confidence'] = conf_part
            
            results.append(result)
        
        return results
    
    def process_blog_entry(self, blog_entry: Dict) -> List[Dict[str, Any]]:
        """Process a single blog entry for LLM annotation"""
        annotations = []
        blog_id = blog_entry.get('blog_id')
        blog_title = blog_entry.get('title', '')
        
        if self.framework == "mitre":
            entries = blog_entry.get('techniques', [])  # Changed from 'technique_entries'
            entry_type = "technique"
            id_field = "technique_id"
            behavior_field = "attack_behavior_text"  # Changed from 'attack_behaviors'
        elif self.framework == "capec":
            entries = blog_entry.get('capec_entries', [])
            entry_type = "CAPEC"
            id_field = "capec_id"
            behavior_field = "attack_patterns"
        elif self.framework == "cve":
            entries = blog_entry.get('cve_entries', [])
            entry_type = "CVE"
            id_field = "cve_id"
            behavior_field = "exploit_contexts"
        else:  # cwe
            entries = blog_entry.get('cwe_entries', [])
            entry_type = "CWE"
            id_field = "cwe_id"
            behavior_field = "vulnerabilities"
        
        # Calculate techniques for this blog
        techniques_in_blog = len(entries)
        print(f"🔍 Processing blog {blog_id}: {blog_title[:50]}... ({techniques_in_blog} {entry_type.lower()}s)")
        
        for entry in entries:
            behavior_id = entry.get('behavior_id', 0)
            entry_id = entry.get(id_field, '')
            behaviors = entry.get(behavior_field, [])
            
            # For MITRE, if attack_behavior_text is a string, convert it to a list
            if self.framework == "mitre" and isinstance(behaviors, str):
                behaviors = [behaviors]
            
            # Check if this technique should be processed based on checkpoint
            if not self.should_process_behavior(blog_entry, behavior_id):
                print(f"  ⏭️  Skipping {entry_type.lower()} {behavior_id} (already processed)")
                continue
            
            print(f"  📋 Analyzing {entry_type.lower()} {behavior_id}...")
            
            # Process each behavior
            for behavior_index, behavior in enumerate(behaviors):
                print(f"    🔄 Processing behavior {behavior_index + 1}/{len(behaviors)}...")
                print(f"    📄 Behavior text length: {len(behavior)} characters")
                
                if self.framework == "mitre":
                    # Use decomposition + RAG strategy for MITRE
                    matches = self.process_mitre_behavior_with_decomposition(behavior, blog_id, behavior_id)
                    
                    # Create annotations for each match
                    for match in matches:
                        annotation = {
                            'technique_id': match['technique_id'],
                            'technique_name': match['technique_name'],
                            'blog_id': blog_id,
                            'blog_title': blog_title,
                            'technique_index': behavior_id,
                            'attack_behavior_text': behavior,
                            'atomic_behavior': match['atomic_behavior'],
                            'behavior_index': match['behavior_index'],
                            'llm_judgment': match['llm_judgment'],
                            'confidence': match['confidence'],
                            'similarity_score': match['similarity'],
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        annotations.append(annotation)
                        
                        # Immediately save this annotation to output file
                        self.save_single_annotation(annotation)
                        
                        print(f"    ✅ Matched to {match['technique_id']} (confidence: {match['confidence']}) - Saved immediately")
                    
                    if not matches:
                        print(f"    ⚠️  No good matches found for any atomic behavior")
                elif self.framework == "capec":
                    # Use direct LLM judgment for CAPEC (no decomposition)
                    matches = self.process_capec_pattern_with_decomposition(behavior, blog_id, behavior_id)
                    
                    # Create annotations for each match
                    for match in matches:
                        annotation = {
                            'capec_id': match['capec_id'],
                            'capec_name': match['capec_name'],
                            'blog_id': blog_id,
                            'blog_title': blog_title,
                            'pattern_index': behavior_id,
                            'attack_pattern_text': behavior,
                            'llm_judgment': match['llm_judgment'],
                            'confidence': match['confidence'],
                            'similarity_score': match['similarity'],
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        annotations.append(annotation)
                        print(f"    💾 Saving annotation to file...")
                        self.save_single_annotation(annotation)
                        print(f"    ✅ Matched to {match['capec_id']} (confidence: {match['confidence']}) - Saved immediately")
                    
                    if not matches:
                        print(f"    ⚠️  No good matches found for CAPEC pattern")
                elif self.framework == "cve":
                    # For CVE, use direct CVE ID matching (no vector search)
                    matches = self.process_cve_exploit_direct(behavior, blog_id, behavior_id, entry_id)
                    
                    # Create annotations for each match
                    for match in matches:
                        annotation = {
                            'cve_id': match['cve_id'],
                            'cve_description': match['cve_description'],
                            'blog_id': blog_id,
                            'blog_title': blog_title,
                            'exploit_index': behavior_id,
                            'exploit_context_text': behavior,
                            'llm_judgment': match['llm_judgment'],
                            'confidence': match['confidence'],
                            'similarity_score': match['similarity'],
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        annotations.append(annotation)
                        self.save_single_annotation(annotation)
                        
                        print(f"    ✅ Matched to {match['cve_id']} (confidence: {match['confidence']}) - Saved immediately")
                    
                    if not matches:
                        print(f"    ⚠️  No CVE matches found")
                else:
                    # CWE path: decompose, get candidates, LLM judge, and filter
                    atomic_behaviors = self._decompose_vulnerability(behavior)
                    all_mapped_cwes: List[Dict[str, Any]] = []
                    for ab_index, atomic_behavior in enumerate(atomic_behaviors, 1):
                        candidates = self.get_candidates(atomic_behavior)
                        # Enrich candidates with full description from corpus
                        enriched_candidates: List[Dict[str, Any]] = []
                        for c in candidates:
                            entry_from_corpus = self.corpus.get(c['id'], {})
                            desc = self._extract_cwe_description(entry_from_corpus) if entry_from_corpus else c.get('description', 'No description')
                            enriched_candidates.append({
                                'id': c['id'],
                                'name': c.get('name', ''),
                                'description': desc,
                                'similarity': c.get('similarity', 0.0)
                            })
                        selected = self._llm_judge_cwe_mapping(behavior, atomic_behavior, enriched_candidates, blog_id, behavior_id)
                        for s in selected:
                            s['atomic_behavior'] = atomic_behavior
                            s['behavior_index'] = ab_index
                            s['blog_id'] = blog_id
                            s['behavior_id'] = behavior_id
                        all_mapped_cwes.extend(selected)
                    if all_mapped_cwes:
                        filtered_best = self._filter_best_cwe_per_behavior(all_mapped_cwes, behavior, blog_id, behavior_id)
                        for mapped in filtered_best:
                            annotation = {
                                'cwe_id': entry_id,
                                'cwe_name': mapped.get('name', ''),
                                'blog_id': blog_id,
                                'blog_title': blog_title,
                                'vulnerability_index': behavior_id,
                                'attack_behavior_text': behavior,
                                'atomic_behavior': mapped.get('atomic_behavior', ''),
                                'behavior_index': mapped.get('behavior_index'),
                                'llm_judgment': 'YES',
                                'confidence': 'HIGH',
                                'similarity_score': mapped.get('similarity', 0.0),
                                'timestamp': datetime.now().isoformat()
                            }
                            annotations.append(annotation)
                            self.save_single_annotation(annotation)
                            print(f"    ✅ Selected CWE-{mapped['id']} for behavior '{mapped.get('atomic_behavior','')[:50]}...' - Saved immediately")
                    else:
                        print(f"    ⚠️  No CWE mappings found by LLM for this vulnerability")
                
                # OPTIMIZATION: Reduced delay since we're batching calls
                time.sleep(0.05)
            
            # Save checkpoint after each technique (for fine-grained recovery)
            self.save_checkpoint(
                blog_id=blog_id,
                behavior_id=behavior_id,
                annotations_count=len(annotations),
                status='processing'
            )
        
        return annotations
    
    def save_single_annotation(self, annotation: Dict[str, Any]) -> bool:
        """Save a single annotation immediately to the output file"""
        try:
            # Ensure output directory exists
            output_path = Path(self.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Append annotation to output file
            with open(self.output_file, 'a', encoding='utf-8') as f:
                json.dump(annotation, f, ensure_ascii=False)
                f.write('\n')
                f.flush()  # Force immediate write to disk
                os.fsync(f.fileno())  # Ensure data is written to disk
            
            return True
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to save annotation immediately: {e}")
            return False
    
    def get_output_file_annotation_count(self) -> int:
        """Get the current number of annotations in the output file"""
        try:
            if not Path(self.output_file).exists():
                return 0
            
            count = 0
            with open(self.output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        count += 1
            
            return count
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to count annotations in output file: {e}")
            return 0
    
    def run_annotation(self, limit: Optional[int] = None) -> bool:
        """Run the complete LLM annotation process with checkpoint support"""
        print(f"🚀 Starting B2F LLM Annotator for {self.framework.upper()}...")
        
        # Show checkpoint status
        self.show_checkpoint_status()
        
        # Check if input file exists
        if not file_exists(str(self.input_file)):
            print(f"❌ Input file not found: {self.input_file}")
            return False
        
        # Load blog data
        blog_entries = load_jsonl(str(self.input_file))
        if not blog_entries:
            print("❌ No blog data loaded")
            return False
        
        # Apply limit if specified
        if limit:
            blog_entries = blog_entries[:limit]
            print(f"📝 Processing limited to {len(blog_entries)} blogs")
        
        # Calculate total techniques across all blogs
        total_techniques_all_blogs = self.calculate_total_techniques(blog_entries)
        print(f"📊 Total techniques across all blogs: {total_techniques_all_blogs}")
        
        # Update checkpoint with total techniques count
        self.save_checkpoint(
            total_techniques=total_techniques_all_blogs,
            status='processing'
        )
        
        # Filter blogs based on checkpoint
        blogs_to_process = []
        for blog_entry in blog_entries:
            if self.should_process_blog(blog_entry):
                blogs_to_process.append(blog_entry)
        
        print(f"🔍 Processing {len(blogs_to_process)} blog entries (from {len(blog_entries)} total)")
        if len(blogs_to_process) < len(blog_entries):
            print(f"⏭️  Skipping {len(blog_entries) - len(blogs_to_process)} already processed blogs")
        
        # Process each blog entry
        processed_count = 0
        total_annotations = 0
        global_processed_techniques = 0
        
        for blog_entry in blogs_to_process:
            try:
                blog_id = blog_entry.get('blog_id')
                print(f"\n📝 Processing blog {processed_count + 1}/{len(blogs_to_process)}: {blog_id}")
                
                # Calculate techniques in this blog
                if self.framework == "mitre":
                    techniques_in_blog = len(blog_entry.get('techniques', []))
                elif self.framework == "capec":
                    techniques_in_blog = len(blog_entry.get('capec_entries', []))
                elif self.framework == "cve":
                    techniques_in_blog = len(blog_entry.get('cve_entries', []))
                else:  # cwe
                    techniques_in_blog = len(blog_entry.get('cwe_entries', []))
                
                annotations = self.process_blog_entry(blog_entry)
                processed_count += 1
                total_annotations += len(annotations)
                global_processed_techniques += techniques_in_blog
                
                # Save checkpoint after each blog
                self.save_checkpoint(
                    blog_id=blog_id,
                    behavior_id=None,  # Will be updated in process_blog_entry
                    processed_techniques=global_processed_techniques,
                    annotations_count=len(annotations),
                    status='processing'
                )
                
                print(f"✅ Completed blog {processed_count}/{len(blogs_to_process)} ({len(annotations)} annotations)")
                print(f"📊 Global progress: {global_processed_techniques}/{total_techniques_all_blogs} techniques")
                
            except Exception as e:
                print(f"❌ Error processing blog {blog_entry.get('blog_id', 'unknown')}: {e}")
                # Save checkpoint even on error
                self.save_checkpoint(
                    blog_id=blog_entry.get('blog_id'),
                    status='error'
                )
                continue
        
        # Final checkpoint update (annotations are already saved individually)
        if total_annotations > 0:
            # Update final checkpoint
            self.save_checkpoint(
                status='completed',
                annotations_count=0  # Don't double count
            )
            
            print(f"\n📊 LLM Annotation Summary ({self.framework.upper()})")
            print(f"Blogs processed in this run: {processed_count}")
            print(f"Annotations generated in this run: {total_annotations}")
            print(f"Total annotations in output file: {self.get_output_file_annotation_count()}")
            print(f"Output saved to: {self.output_file}")
            print(f"💾 Note: Each annotation was saved immediately during processing")
            return True
        else:
            print("❌ No new annotations generated")
            return False
    
    def run(self, limit: Optional[int] = None) -> bool:
        """Run the complete LLM annotation process"""
        print("=" * 50)
        print(f"B2F LLM Annotator ({self.framework.upper()})")
        print("=" * 50)
        
        # Show initial status
        self.show_checkpoint_status()
        
        success = self.run_annotation(limit)
        
        if success:
            print(f"\n🎉 LLM annotation completed successfully for {self.framework.upper()}!")
            # Show final status
            self.show_checkpoint_status()
            # Print LLM call summary
            print_llm_call_summary()
        else:
            print(f"\n❌ LLM annotation failed!")
            # Print LLM call summary even on failure
            print_llm_call_summary()
        
        return success

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="B2F LLM Annotator - LLM-powered annotation")
    parser.add_argument("--limit", type=int, help="Number of blogs to process")
    parser.add_argument("--framework", type=str, default="cwe", choices=["cwe", "mitre", "capec", "cve"], 
                       help="Framework to use: cwe, mitre, capec, or cve (default: cwe)")
    parser.add_argument("--force-restart", action="store_true", help="Force restart annotation process")
    
    args = parser.parse_args()
    
    try:
        annotator = LLMAnnotator(framework=args.framework, force_restart=args.force_restart)
        success = annotator.run(limit=args.limit)
        
        if success:
            print(f"\n🎉 B2F LLM Annotator completed successfully for {args.framework.upper()}!")
        else:
            print(f"\n❌ B2F LLM Annotator encountered errors")
            
    except Exception as e:
        print(f"❌ Failed to initialize B2F LLM Annotator: {e}")

if __name__ == "__main__":
    main()
