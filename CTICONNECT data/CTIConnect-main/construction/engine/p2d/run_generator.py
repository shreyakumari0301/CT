#!/usr/bin/env python3
"""
Command-line script to run the p2d data generator.

Processes prompts through LLM APIs to generate structured JSON data for RAG benchmarking.
"""

import argparse
import sys
from pathlib import Path

# Add the project root to the path so we can import the generator
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from construction.engine.p2d.data_generator import DataGenerator



def main():
    """Main entry point for the command-line script."""
    parser = argparse.ArgumentParser(
        description="Generate data using prompts through LLM APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with OpenAI (default) - creates timestamped output directory
  python dataset_generation/engine/p2d_1/run_generator.py --task rcm --template-version v1 --batch-id batch_1
  
  # Use specific directory paths (no timestamp)
  python dataset_generation/engine/p2d_1/run_generator.py \\
    --prompt-dir dataset_generation/prompts/rcm/v1/batch_1 \\
    --output-dir dataset_generation/data/rcm/v1/batch_1 \\
    --no-timestamp
  
  # Use specific model
  python dataset_generation/engine/p2d_1/run_generator.py \\
    --task rcm --template-version v1 --batch-id batch_1 \\
    --provider openai --model gpt-5
        """
    )
    
    # Path structure arguments
    parser.add_argument(
        "--task",
        default="rcm",
        help="Task type (e.g., rcm, cca, csc, eea) (default: rcm)"
    )
    
    parser.add_argument(
        "--template-version",
        default="v1",
        help="Template version (e.g., v1, v2, v3) (default: v1)"
    )
    
    parser.add_argument(
        "--batch-id",
        help="Batch identifier (e.g., batch_1, 1) (optional)"
    )

    # Custom directory overrides
    parser.add_argument(
        "--prompt-dir",
        help="Custom prompt directory (overrides path construction from task/version/batch)"
    )

    parser.add_argument(
        "--output-dir",
        help="Custom output directory (overrides path construction from task/version/batch)"
    )

    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Don't add timestamp to output directory"
    )

    parser.add_argument(
        "--model",
        help="Model name (optional, default: o4-mini)"
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum number of retries for failed calls (default: 3)"
    )
    
    parser.add_argument(
        "--max-jobs",
        type=int,
        help="Maximum number of jobs to process (optional, processes all if not specified)"
    )
    
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        default=True,
        help="Skip files that already exist (default: True)"
    )
    
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files"
    )
    
    args = parser.parse_args()
    
    # Create generator with specified parameters
    generator = DataGenerator(
        task=args.task,
        template_version=args.template_version,
        batch_id=args.batch_id,
        prompt_dir=args.prompt_dir,
        output_dir=args.output_dir,
        model=args.model,
        max_retries=args.max_retries,
        max_jobs=args.max_jobs,
        add_timestamp=not args.no_timestamp,
    )

    # Print configuration
    print("Starting p2d data generation...")
    print(f"Task: {args.task}")
    print(f"Template version: {args.template_version}")
    print(f"Batch ID: {args.batch_id or 'None'}")
    print(f"Model: {args.model or 'default'}")
    print(f"Prompt directory: {generator.prompt_dir}")
    print(f"Output directory: {generator.output_dir}")
    print(f"Max retries: {args.max_retries}")
    print(f"Max jobs: {args.max_jobs or 'All'}")
    print(f"Skip existing: {not args.overwrite}")
    print()
    
    # Run the generation process
    generator.run(skip_existing=not args.overwrite)
    print("Data generation completed!")


if __name__ == "__main__":
    main()
