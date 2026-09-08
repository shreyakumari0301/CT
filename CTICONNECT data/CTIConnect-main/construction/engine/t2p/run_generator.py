#!/usr/bin/env python3
"""
Command-line script to run the simplified prompt generator.
"""

import argparse
import sys
from pathlib import Path
from generator import PromptGenerator
# Add the project root to the path so we can import the generator
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


def main():
    """Main entry point for the command-line script."""
    parser = argparse.ArgumentParser(
        description="Generate relationship prompts using Jinja2 templates"
    )
    
    parser.add_argument(
        "--corpus-dir", 
        default="corpus_kb",
        help="Path to corpus directory (default: corpus_kb)"
    )
    
    parser.add_argument(
        "--correlation-dir",
        default="correlation", 
        help="Path to correlation data directory (default: correlation)"
    )
    
    parser.add_argument(
        "--template-dir",
        default="dataset_generation/templates",
        help="Path to Jinja2 template directory (default: dataset_generation/templates)"
    )

    parser.add_argument(
        "--output-dir",
        default="dataset_generation/prompts",
        help="Directory to save generated prompts (default: dataset_generation/prompts)"
    )
    
    parser.add_argument(
        "--task",
        default="rcm",
        help="Task identifier (default: rcm). Examples: rcm, cca, csc, eea, vca, ata, tap, mla"
    )

    parser.add_argument(
        "--template-version",
        default="v1",
        help="Version of the template (default: v1). Examples: v1, v2, v5"
    )

    parser.add_argument(
        "--enable-batching",
        action="store_true",
        help="Enable random batching of generated prompts"
    )
    
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of prompts per batch (default: 100)"
    )
    
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Remove existing files in output directory before generation"
    )
    
    parser.add_argument(
        "--blog-cluster-file",
        help="Path to BlogCluster.csv file for CSC/TAP/MLA tasks (default: datasets/BlogCluster.csv)"
    )
    
    args = parser.parse_args()
    
    # Create generator with specified paths
    generator = PromptGenerator(
        corpus_dir=args.corpus_dir,
        correlation_dir=args.correlation_dir,
        template_dir=args.template_dir,
        output_dir=args.output_dir,
        task=args.task,
        template_version=args.template_version,
        enable_batching=args.enable_batching,
        batch_size=args.batch_size,
        restart=args.restart,
        blog_cluster_file=args.blog_cluster_file,
    )

    # Run the generation process
    print("Starting prompt generation...")
    print(f"  Task: {args.task}")
    print(f"  Template version: {args.template_version}")
    print(f"  Batching: {'Enabled' if args.enable_batching else 'Disabled'}")
    if args.enable_batching:
        print(f"  Batch size: {args.batch_size}")
    print(f"  Restart: {'Enabled' if args.restart else 'Disabled'}")
    print(f"  Output: dataset_generation/prompts/{args.task}/{args.template_version}/")
    print()
    
    generator.run()
    print("Prompt generation completed!")


if __name__ == "__main__":
    main()