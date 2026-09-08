"""
LLM utility functions for B2F repository
"""

import os
import time
from typing import Dict, Any, Optional
import openai
import tiktoken
from dotenv import load_dotenv
from datetime import datetime
import sys

# Load environment variables
load_dotenv()

# Global LLM call counter and logger
_llm_call_log = []
_llm_call_counter = 0

def setup_openai_client() -> openai.OpenAI:
    """Setup OpenAI client with API key"""
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY not found in environment variables")
    
    try:
        client = openai.OpenAI(api_key=api_key)
        print("✅ OpenAI client initialized successfully")
        return client
    except Exception as e:
        print(f"❌ Error initializing OpenAI client: {e}")
        raise

def count_tokens(text: str, model: str = "cl100k_base") -> int:
    """Count tokens in text using tiktoken"""
    try:
        encoding = tiktoken.get_encoding(model)
        return len(encoding.encode(text))
    except Exception as e:
        print(f"⚠️  Warning: Error counting tokens: {e}")
        return len(text.split())  # Fallback to word count

def truncate_text(text: str, max_tokens: int, model: str = "cl100k_base") -> str:
    """Truncate text to fit within token limit"""
    tokens = count_tokens(text, model)
    if tokens <= max_tokens:
        return text
    
    # Truncate to max_tokens, leaving some buffer for prompts
    encoding = tiktoken.get_encoding(model)
    truncated_tokens = encoding.encode(text)[:max_tokens - 1000]  # Leave 1000 tokens for prompts
    return encoding.decode(truncated_tokens)

def call_llm_api(
    client: openai.OpenAI,
    prompt: str, 
    system_prompt: str = None,
    model: str = "o3-mini",
    max_tokens: int = 2000,
    temperature: float = 0.1,
    max_retries: int = 3,
    call_type: str = "unknown"  # Track call type: "decomposition", "judgment", "batch_judgment", etc.
) -> Optional[str]:
    """Make a call to LLM API with retry logic and detailed logging"""
    global _llm_call_counter, _llm_call_log
    
    _llm_call_counter += 1
    call_id = _llm_call_counter
    start_time = time.time()
    timestamp = datetime.now().isoformat()
    
    # Estimate tokens
    input_tokens = count_tokens(prompt)
    if system_prompt:
        input_tokens += count_tokens(system_prompt)
    
    # Log call start
    log_entry = {
        'call_id': call_id,
        'timestamp': timestamp,
        'call_type': call_type,
        'model': model,
        'input_tokens': input_tokens,
        'max_tokens': max_tokens,
        'prompt_preview': prompt[:200] + "..." if len(prompt) > 200 else prompt,
        'status': 'started'
    }
    _llm_call_log.append(log_entry)
    
    # Print to stderr so it doesn't interfere with normal output
    print(f"\n[LLM CALL #{call_id}] {call_type.upper()} | Model: {model} | Input tokens: ~{input_tokens} | Started: {timestamp}", file=sys.stderr)
    if len(prompt) > 200:
        print(f"[LLM CALL #{call_id}] Prompt preview: {prompt[:200]}...", file=sys.stderr)
    else:
        print(f"[LLM CALL #{call_id}] Prompt: {prompt}", file=sys.stderr)
    
    for attempt in range(max_retries):
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            # Use max_completion_tokens instead of max_tokens for newer models
            # o3-mini doesn't support temperature parameter
            if model.startswith("o3-"):
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_completion_tokens=max_tokens
                )
            else:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
            
            elapsed_time = time.time() - start_time
            result_text = response.choices[0].message.content.strip()
            output_tokens = count_tokens(result_text)
            
            # Update log entry
            log_entry.update({
                'status': 'success',
                'elapsed_time': elapsed_time,
                'output_tokens': output_tokens,
                'attempts': attempt + 1,
                'response_preview': result_text[:200] + "..." if len(result_text) > 200 else result_text
            })
            
            print(f"[LLM CALL #{call_id}] ✅ SUCCESS | Time: {elapsed_time:.2f}s | Output tokens: ~{output_tokens} | Attempts: {attempt + 1}", file=sys.stderr)
            
            return result_text
            
        except Exception as e:
            elapsed_time = time.time() - start_time
            print(f"[LLM CALL #{call_id}] ⚠️  FAILED (attempt {attempt + 1}/{max_retries}): {e} | Elapsed: {elapsed_time:.2f}s", file=sys.stderr)
            
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"[LLM CALL #{call_id}] Waiting {wait_time}s before retry...", file=sys.stderr)
                time.sleep(wait_time)  # Exponential backoff
            else:
                log_entry.update({
                    'status': 'failed',
                    'elapsed_time': elapsed_time,
                    'attempts': max_retries,
                    'error': str(e)
                })
                print(f"[LLM CALL #{call_id}] ❌ All retry attempts failed", file=sys.stderr)
                return None
    
    return None

def get_llm_call_log() -> list:
    """Get all LLM call logs"""
    return _llm_call_log.copy()

def print_llm_call_summary():
    """Print summary of all LLM calls"""
    if not _llm_call_log:
        print("No LLM calls recorded yet.")
        return
    
    total_calls = len(_llm_call_log)
    successful_calls = sum(1 for log in _llm_call_log if log.get('status') == 'success')
    failed_calls = total_calls - successful_calls
    
    total_time = sum(log.get('elapsed_time', 0) for log in _llm_call_log if 'elapsed_time' in log)
    total_input_tokens = sum(log.get('input_tokens', 0) for log in _llm_call_log)
    total_output_tokens = sum(log.get('output_tokens', 0) for log in _llm_call_log)
    
    print("\n" + "="*80)
    print("LLM CALL SUMMARY")
    print("="*80)
    print(f"Total calls: {total_calls}")
    print(f"Successful: {successful_calls}")
    print(f"Failed: {failed_calls}")
    print(f"Total time: {total_time:.2f}s ({total_time/60:.2f} minutes)")
    print(f"Total input tokens: ~{total_input_tokens}")
    print(f"Total output tokens: ~{total_output_tokens}")
    print(f"Average time per call: {total_time/total_calls:.2f}s" if total_calls > 0 else "")
    
    # Group by call type
    by_type = {}
    for log in _llm_call_log:
        call_type = log.get('call_type', 'unknown')
        if call_type not in by_type:
            by_type[call_type] = {'count': 0, 'time': 0}
        by_type[call_type]['count'] += 1
        if 'elapsed_time' in log:
            by_type[call_type]['time'] += log['elapsed_time']
    
    print("\nBy call type:")
    for call_type, stats in by_type.items():
        avg_time = stats['time'] / stats['count'] if stats['count'] > 0 else 0
        print(f"  {call_type}: {stats['count']} calls, {stats['time']:.2f}s total, {avg_time:.2f}s avg")
    
    print("="*80)

def reset_llm_call_log():
    """Reset the LLM call log"""
    global _llm_call_counter, _llm_call_log
    _llm_call_counter = 0
    _llm_call_log = []

def get_cwe_mapping_prompt(vulnerability_text: str) -> str:
    """Generate prompt for CWE mapping"""
    return f"""Analyze the following vulnerability description and identify the most appropriate CWE (Common Weakness Enumeration) entry.

Vulnerability Description:
{vulnerability_text}

Please provide your analysis in the following format:
CWE_ID: [CWE number, e.g., CWE-123]
CWE_NAME: [Official CWE name]
REASONING: [Brief explanation of why this CWE matches the vulnerability]
CONFIDENCE: [High/Medium/Low]"""

def get_behavior_decomposition_prompt(vulnerability_text: str) -> str:
    """Generate prompt for behavior decomposition"""
    return f"""Decompose the following vulnerability description into atomic behaviors.

Vulnerability Description:
{vulnerability_text}

Please break this down into 3-5 specific, actionable atomic behaviors. Each behavior should be:
- Specific and concrete
- Actionable and measurable
- Related to a specific security weakness

Format your response as:
1. [Atomic behavior 1]
2. [Atomic behavior 2]
3. [Atomic behavior 3]
..."""
