#!/usr/bin/env python3
"""
Data Generator for processing prompts through LLM APIs.

Processes prompts from the generated files and calls LLM services to produce 
structured JSON responses for RAG benchmarking. Supports multiple correlation 
types including CAPEC, MITRE ATT&CK, CVE, and CWE relationships.
"""

import os
import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import time
from dataclasses import dataclass
from datetime import datetime

from .llm_client import LLMClientFactory, BaseLLMClient, LLMResponse


@dataclass
class GenerationJob:
    """Represents a single prompt-to-data generation job."""
    prompt_file: Path
    output_file: Path
    source_id: str
    target_id: str
    
    @classmethod
    def from_prompt_file(cls, prompt_file: Path, output_dir: Path) -> 'GenerationJob':
        """Create generation job from prompt file path."""
        # Extract source and target IDs from filename (new prefixed format)
        # Supported new style: {SRC}-{TGT}.txt where SRC/TGT include prefixes and may contain hyphens
        #   Blog:   BLOG-YYYY-NNNN (e.g., BLOG-2017-5754)
        #   CVE:   CVE-YYYY-NNNN (e.g., CVE-2017-5754)
        #   CWE:   CWE-\d+       (e.g., CWE-1037)
        #   CAPEC: CAPEC-\d+     (e.g., CAPEC-658)
        #   MITRE: T\d+(\.\d+)? (e.g., T1003.001 or T1002)
        # Legacy formats are still supported as fallback.
        filename = prompt_file.stem

        id_patterns = [
            r'CVE-\d{4}-\d+',
            r'CWE-\d+',
            r'CAPEC-\d+',
            r'T\d+(?:\.\d+)?',
            r'BLOG-\d+'
        ]
        target_regex = re.compile(r'(' + '|'.join(id_patterns) + r')$')
        source_regex = re.compile(r'^(' + '|'.join(id_patterns) + r')$')

        source_id = filename
        target_id = ""

        # Try to identify target ID at the end
        m_tgt = target_regex.search(filename)
        if m_tgt:
            target_id = m_tgt.group(1)
            # Expect a hyphen separator before target
            sep_index = filename.rfind('-' + target_id)
            if sep_index > 0:
                candidate_source = filename[:sep_index]
                # Validate source matches one of the allowed patterns
                if source_regex.match(candidate_source):
                    source_id = candidate_source
                else:
                    # Fallback: keep entire stem as source if not matched
                    source_id = filename
                    target_id = ""
        
        # Generate output filename
        if target_id:
            # Standard format: src-tgt.json
            output_filename = f"{source_id}-{target_id}.json"
        else:
            # Single ID format: source_id.json
            output_filename = f"{source_id}.json"
        
        output_file = output_dir / output_filename
        
        return cls(
            prompt_file=prompt_file,
            output_file=output_file,
            source_id=source_id,
            target_id=target_id
        )


@dataclass
class GenerationResult:
    """Result of a generation job."""
    job: GenerationJob
    llm_response: LLMResponse
    success: bool
    error_message: Optional[str] = None
    processing_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source_id": self.job.source_id,
            "target_id": self.job.target_id,
            "prompt_file": str(self.job.prompt_file),
            "output_file": str(self.job.output_file),
            "success": self.success,
            "error_message": self.error_message,
            "processing_time": self.processing_time,
            "llm_response": {
                "content": self.llm_response.content,
                "model": self.llm_response.model,
                "usage": self.llm_response.usage,
                "error": self.llm_response.error
            }
        }


class DataGenerator:
    """Generator for processing prompts through LLM APIs to create structured data."""
    
    def __init__(self,
                 task: str = "rcm",
                 template_version: str = "v1",
                 batch_id: Optional[str] = None,
                 prompt_dir: Optional[str] = None,
                 output_dir: Optional[str] = None,
                 model: Optional[str] = None,
                 max_retries: int = 3,
                 max_jobs: Optional[int] = None,
                 add_timestamp: bool = True):
        """
        Initialize the data generator.

        Args:
            task: Task type (e.g., "rcm", "cca", "csc", "eea")
            template_version: Template version (e.g., "v1", "v2")
            batch_id: Batch identifier (e.g., "batch_1", "1")
            prompt_dir: Custom prompt directory (overrides path construction)
            output_dir: Custom output directory (overrides path construction)
            model: Model name (optional, uses defaults)
            max_retries: Maximum number of retries for failed calls
            max_jobs: Maximum number of jobs to process (optional, processes all if not specified)
            add_timestamp: Whether to add timestamp to output directory
        """
        self.task = task
        self.template_version = template_version
        self.batch_id = batch_id
        self.model = model or "o4-mini"
        self.rate_limit_delay = 0.0  # user confirmed no token-rate constraint
        self.max_retries = max_retries
        self.max_jobs = max_jobs
        self.add_timestamp = add_timestamp
        
        # Set up directory paths
        if prompt_dir:
            self.prompt_dir = Path(prompt_dir)
        else:
            self.prompt_dir = self._construct_prompt_path()
            
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self._construct_output_path()
        
        # Initialize LLM client
        self.llm_client: Optional[BaseLLMClient] = None
        
        # Generation statistics
        self.stats = {
            "total_jobs": 0,
            "successful": 0,
            "failed": 0,
            "skipped": 0,
            "total_tokens": 0,
            "total_cost": 0.0,
            "processing_time": 0.0,
            "start_time": None,
            "end_time": None
        }
    
    def _construct_prompt_path(self) -> Path:
        """Construct prompt directory path from task, version, and batch."""
        base_path = f"dataset_generation/prompts/{self.task}/{self.template_version}"
        if self.batch_id:
            return Path(base_path) / self.batch_id
        return Path(base_path)

    def _construct_output_path(self) -> Path:
        """Construct output directory path from task, version, and batch."""
        base_path = f"dataset_generation/data/{self.task}/{self.template_version}"
        if self.batch_id:
            base_path += f"/{self.batch_id}"
        if self.add_timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_path += f"_{timestamp}"
        return Path(base_path)
    
    def load_env_variables(self) -> None:
        """Load environment variables from .env file if it exists."""
        env_file = Path(".env")
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
    
    def initialize_llm_client(self) -> None:
        """Initialize the LLM client."""
        print(f"Initializing OpenAI client...")
        
        try:
            self.llm_client = LLMClientFactory.create_client(
                model=self.model,
                api_key=os.getenv("OPENAI_API_KEY"),
            )
            print(f"Successfully initialized OpenAI client with model: {self.llm_client.model}")
        except Exception as e:
            print(f"Error initializing LLM client: {e}", file=sys.stderr)
            raise
    
    def discover_prompt_files(self) -> List[Path]:
        """Discover all prompt files in the prompt directory."""
        if not self.prompt_dir.exists():
            raise FileNotFoundError(f"Prompt directory not found: {self.prompt_dir}")
        
        # Find all .txt files
        prompt_files = list(self.prompt_dir.glob("*.txt"))
        
        if not prompt_files:
            raise FileNotFoundError(f"No prompt files (*.txt) found in: {self.prompt_dir}")
        
        prompt_files.sort()  # Ensure consistent ordering
        
        print(f"Discovered {len(prompt_files)} prompt files")
        return prompt_files
    
    def create_generation_jobs(self, prompt_files: List[Path]) -> List[GenerationJob]:
        """Create generation jobs from prompt files."""
        jobs = []
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        for prompt_file in prompt_files:
            try:
                job = GenerationJob.from_prompt_file(prompt_file, self.output_dir)
                jobs.append(job)
            except ValueError as e:
                print(f"Warning: Skipping invalid prompt file {prompt_file}: {e}", file=sys.stderr)
        
        return jobs
    
    def load_prompt(self, prompt_file: Path) -> str:
        """Load prompt content from file."""
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception as e:
            raise RuntimeError(f"Error loading prompt from {prompt_file}: {e}")
    
    def clean_json_content(self, content: str) -> str:
        """Clean JSON content by removing code block markers and extra text."""
        content = content.strip()
        
        # Remove common non-JSON prefixes that LLMs might add
        prefixes_to_remove = [
            "## OUTPUT",
            "## RESPONSE",
            "## RESULT", 
            "**RESPONSE:**",
            "**OUTPUT:**",
            "Here's the JSON:",
            "Here is the JSON:",
            "```json",
            "```"
        ]
        
        lines = content.split('\n')
        start_line = 0
        
        # Find the actual start of JSON by skipping non-JSON lines
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip empty lines and common prefixes
            if not line_stripped:
                continue
            
            # Check if this line starts with any prefix to remove
            skip_line = False
            for prefix in prefixes_to_remove:
                if line_stripped.startswith(prefix):
                    skip_line = True
                    break
            
            if skip_line:
                continue
                
            # If we find a line that starts with {, this is likely our JSON start
            if line_stripped.startswith('{'):
                start_line = i
                break
        
        # Take content from the JSON start
        if start_line < len(lines):
            content = '\n'.join(lines[start_line:])
        
        # Remove closing ``` markers and any trailing non-JSON content
        lines = content.split('\n')
        end_line = len(lines)
        
        # Find the last } which should be the end of our JSON
        for i in range(len(lines) - 1, -1, -1):
            line_stripped = lines[i].strip()
            if line_stripped == '}':
                end_line = i + 1
                break
            elif line_stripped == '```' or line_stripped.startswith('```'):
                # Skip this line and continue looking for }
                end_line = i
                continue
        
        # Take content up to the JSON end
        if end_line <= len(lines):
            content = '\n'.join(lines[:end_line])
        
        return content.strip()
    
    def save_data(self, data: str, output_file: Path) -> None:
        """Save generated data to file after cleaning JSON markers."""
        try:
            # Clean the JSON content
            cleaned_data = self.clean_json_content(data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(cleaned_data)
        except Exception as e:
            raise RuntimeError(f"Error saving data to {output_file}: {e}")

    # -------------------- Billing helpers --------------------
    def _compute_openai_gpt5_cost(self, usage: Dict[str, Any]) -> Dict[str, Any]:
        """Compute cost breakdown for OpenAI gpt-5 using usage details.

        Pricing (per 1M tokens): Input $1.25, Cached Input $0.125, Output $10.00
        """
        if not usage:
            return {
                "tokens": {"input": 0, "cached_input": 0, "output": 0},
                "unit_prices": {"input": 1.25, "cached_input": 0.125, "output": 10.0},
                "costs": {"input": 0.0, "cached_input": 0.0, "output": 0.0},
                "total": 0.0,
            }

        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage.get("completion_tokens", 0) or 0)
        cached_tokens = 0
        try:
            details = usage.get("prompt_tokens_details", {}) or {}
            cached_tokens = int(details.get("cached_tokens", 0) or 0)
        except Exception:
            cached_tokens = 0

        non_cached_input = max(prompt_tokens - cached_tokens, 0)
        output_tokens = completion_tokens

        # Prices per 1M tokens
        price_input = 1.25
        price_cached = 0.125
        price_output = 10.0

        def per_token_cost(tokens: int, per_million: float) -> float:
            return (tokens * per_million) / 1_000_000.0

        cost_input = per_token_cost(non_cached_input, price_input)
        cost_cached = per_token_cost(cached_tokens, price_cached)
        cost_output = per_token_cost(output_tokens, price_output)
        total_cost = cost_input + cost_cached + cost_output

        return {
            "tokens": {
                "input": non_cached_input,
                "cached_input": cached_tokens,
                "output": output_tokens,
            },
            "unit_prices": {
                "input": price_input,
                "cached_input": price_cached,
                "output": price_output,
            },
            "costs": {
                "input": round(cost_input, 6),
                "cached_input": round(cost_cached, 6),
                "output": round(cost_output, 6),
            },
            "total": round(total_cost, 6),
        }

    def _augment_json_with_billing(self, content: str, usage: Dict[str, Any], billing: Optional[Dict[str, Any]] = None, api_call_seconds: Optional[float] = None) -> str:
        """Insert usage, optional billing, and optional timing info into the model JSON output."""
        try:
            obj = json.loads(content)
            # obj["llm_usage"] = usage or {}
            if billing:
                obj["llm_cost"] = {
                    "input": billing["costs"]["input"],
                    "cached_input": billing["costs"]["cached_input"],
                    "output": billing["costs"]["output"],
                    "total": billing["total"],
                    "unit_prices_per_million_tokens": billing["unit_prices"],
                    "tokens": billing["tokens"],
                }
            if api_call_seconds is not None:
                obj["llm_timing"] = {"api_call_seconds": round(float(api_call_seconds), 4)}
            
            return json.dumps(obj, indent=2)
        except Exception:
            # If parsing fails, return original content
            return content
    
    def process_job(self, job: GenerationJob, skip_existing: bool = True) -> GenerationResult:
        """Process a single generation job."""
        start_time = time.time()
        
        try:
            # Check if output already exists
            if skip_existing and job.output_file.exists():
                print(f"Skipping {job.source_id}->{job.target_id} (output exists)")
                self.stats["skipped"] += 1
                return GenerationResult(
                    job=job,
                    llm_response=LLMResponse(content="", model="", error="Output already exists"),
                    success=False,
                    error_message="Output already exists",
                    processing_time=0.0
                )
            
            # Load prompt
            prompt = self.load_prompt(job.prompt_file)
            
            # Check prompt length (rough estimate: 1 token ≈ 4 characters)
            prompt_length_chars = len(prompt)
            estimated_tokens = prompt_length_chars // 4
            
            # If prompt is too long, skip it
            if estimated_tokens > 100000:  # Leave room for response tokens (GPT-4 has 128K context)
                print(f"Skipping {job.source_id}->{job.target_id} (prompt too long: ~{estimated_tokens} tokens)")
                self.stats["skipped"] += 1
                return GenerationResult(
                    job=job,
                    llm_response=LLMResponse(content="", model="", error="Prompt too long"),
                    success=False,
                    error_message=f"Prompt too long (~{estimated_tokens} tokens)",
                    processing_time=time.time() - start_time
                )
            
            # Generate data with retries
            llm_response = None
            last_api_call_seconds: Optional[float] = None
            for attempt in range(self.max_retries):
                try:
                    api_start = time.monotonic()
                    llm_response = self.llm_client.generate(prompt)
                    last_api_call_seconds = time.monotonic() - api_start
                    
                    if llm_response.is_success:
                        if last_api_call_seconds is not None:
                            print(f"Successfully generated data for {job.source_id}->{job.target_id} in {last_api_call_seconds:.2f}s")
                        break
                    else:
                        print(f"Attempt {attempt + 1} failed for {job.source_id}->{job.target_id}: {llm_response.error}")
                        if attempt < self.max_retries - 1:
                            time.sleep(self.rate_limit_delay * (attempt + 1))  # Exponential backoff
                
                except Exception as e:
                    print(f"Attempt {attempt + 1} exception for {job.source_id}->{job.target_id}: {e}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.rate_limit_delay * (attempt + 1))
            
            if not llm_response or not llm_response.is_success:
                error_msg = llm_response.error if llm_response else "Unknown error"
                
                # Check if it's a context length error
                if "context_length_exceeded" in error_msg or "maximum context length" in error_msg:
                    print(f"Skipping {job.source_id}->{job.target_id} (context length exceeded)")
                    self.stats["skipped"] += 1
                    return GenerationResult(
                        job=job,
                        llm_response=llm_response or LLMResponse(content="", model="", error="Context length exceeded"),
                        success=False,
                        error_message="Context length exceeded",
                        processing_time=time.time() - start_time
                    )
                
                return GenerationResult(
                    job=job,
                    llm_response=llm_response or LLMResponse(content="", model="", error="No response"),
                    success=False,
                    error_message=error_msg,
                    processing_time=time.time() - start_time
                )
            
            # Compute billing if OpenAI gpt-5, always include timing
            content_to_save = llm_response.content
            if isinstance(self.llm_client, BaseLLMClient) and "gpt-5" in (self.llm_client.model or "").lower():
                billing = self._compute_openai_gpt5_cost(llm_response.usage or {})
                # Update stats
                self.stats["total_cost"] += billing["total"]
                # Clean JSON then augment with billing info
                cleaned = self.clean_json_content(llm_response.content)
                content_to_save = self._augment_json_with_billing(cleaned, llm_response.usage or {}, billing, last_api_call_seconds)
            else:
                cleaned = self.clean_json_content(llm_response.content)
                content_to_save = self._augment_json_with_billing(cleaned, llm_response.usage or {}, None, last_api_call_seconds)

            # Save generated data
            self.save_data(content_to_save, job.output_file)

            # Update statistics
            self.stats["successful"] += 1
            if llm_response.usage:
                self.stats["total_tokens"] += llm_response.usage.get("total_tokens", 0)
            
            processing_time = time.time() - start_time
            self.stats["processing_time"] += processing_time
            
            return GenerationResult(
                job=job,
                llm_response=llm_response,
                success=True,
                processing_time=processing_time
            )
            
        except Exception as e:
            error_msg = str(e)
            self.stats["failed"] += 1
            
            return GenerationResult(
                job=job,
                llm_response=LLMResponse(content="", model="", error=error_msg),
                success=False,
                error_message=error_msg,
                processing_time=time.time() - start_time
            )
    
    def generate_all_data(self, skip_existing: bool = True) -> List[GenerationResult]:
        """Generate data for all prompts."""
        if not self.llm_client:
            raise RuntimeError("LLM client not initialized. Call initialize_llm_client() first.")
        
        self.stats["start_time"] = datetime.now().isoformat()
        
        prompt_files = self.discover_prompt_files()
        jobs = self.create_generation_jobs(prompt_files)
        
        # Apply max_jobs limit if specified
        if self.max_jobs is not None:
            jobs = jobs[:self.max_jobs]
            print(f"Limiting processing to {self.max_jobs} jobs (out of {len(prompt_files)} total files)")
        
        self.stats["total_jobs"] = len(jobs)
        results = []
        
        print(f"Processing {len(jobs)} generation jobs...")
        
        for i, job in enumerate(jobs, 1):
            print(f"Processing {i}/{len(jobs)}: {job.source_id} -> {job.target_id}")
            
            result = self.process_job(job, skip_existing)
            results.append(result)
            
            # Rate limiting
            if result.success:
                time.sleep(self.rate_limit_delay)
            
            # Progress updates
            if i % 10 == 0:
                print(f"Progress: {i}/{len(jobs)} jobs processed")
                print(f"  Success: {self.stats['successful']}, Failed: {self.stats['failed']}, Skipped: {self.stats['skipped']}")
        
        self.stats["end_time"] = datetime.now().isoformat()
        return results
    
    def save_generation_report(self, results: List[GenerationResult]) -> None:
        """Save generation report with statistics and results."""
        report_file = self.output_dir / "generation_report.json"
        
        report = {
            "generation_statistics": self.stats,
            "configuration": {
                "task": self.task,
                "template_version": self.template_version,
                "batch_id": self.batch_id,
                "provider": "openai",
                "model": self.llm_client.model if self.llm_client else None,
                "prompt_dir": str(self.prompt_dir),
                "output_dir": str(self.output_dir),
                "rate_limit_delay": self.rate_limit_delay,
                "max_retries": self.max_retries,
                "max_jobs": self.max_jobs,
            },
            "results": [result.to_dict() for result in results]
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"Generation report saved to: {report_file}")
    
    def run(self, skip_existing: bool = True) -> None:
        """Run the complete data generation process."""
        try:
            # Load environment variables
            self.load_env_variables()
            
            # Initialize LLM client
            self.initialize_llm_client()
            
            # Generate all data
            results = self.generate_all_data(skip_existing)
            
            # Save report
            self.save_generation_report(results)
            
            # Print summary
            print(f"\nGeneration complete:")
            print(f"  Task: {self.task}")
            print(f"  Template version: {self.template_version}")
            print(f"  Batch ID: {self.batch_id}")
            print(f"  Total jobs: {self.stats['total_jobs']}")
            print(f"  Successful: {self.stats['successful']}")
            print(f"  Failed: {self.stats['failed']}")
            print(f"  Skipped: {self.stats['skipped']}")
            print(f"  Total tokens: {self.stats['total_tokens']}")
            print(f"  Total processing time: {self.stats['processing_time']:.2f}s")
            print(f"  Output directory: {self.output_dir}")
            
        except Exception as e:
            print(f"Error during data generation: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Main entry point for the data generator."""
    generator = DataGenerator()
    generator.run()


if __name__ == "__main__":
    main()
