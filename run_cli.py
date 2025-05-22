#!/usr/bin/env python
"""
CLI entry point for the CodeScanAI tool.
"""

import os
import sys
import logging
import argparse

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.runner import run_security_pipeline, format_pipeline_results

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="CodeScanAI CLI")

    # Directory to scan
    parser.add_argument("--directory", type=str, required=True, help="Directory to scan")

    # Scan options
    parser.add_argument("--sast", action="store_true", help="Run SAST scan")
    parser.add_argument("--sca", action="store_true", help="Run SCA scan")
    parser.add_argument("--dast", action="store_true", help="Run DAST scan")
    parser.add_argument("--changes-only", action="store_true", help="Only scan changed files")

    # DAST options
    parser.add_argument("--target-url", type=str, help="Target URL for DAST scanning")
    parser.add_argument("--zap-path", type=str, help="Path to ZAP installation for DAST scanning")
    parser.add_argument("--zap-api-key", type=str, help="API key for ZAP")
    parser.add_argument("--use-basic-scanner", action="store_true", help="Use basic scanner instead of ZAP for DAST")

    # Fix options
    parser.add_argument("--fix", action="store_true", help="Generate fixes for vulnerabilities")
    parser.add_argument("--validate", action="store_true", help="Validate generated fixes")

    # Model options
    parser.add_argument("--provider", type=str, default="huggingface",
                        choices=["openai", "gemini", "huggingface", "custom"],
                        help="AI provider to use for generating fixes")
    parser.add_argument("--model", type=str, default="mistralai/Mistral-7B-Instruct-v0.3", help="Model to use for generating fixes and scanning")

    # GitHub options
    parser.add_argument("--github-token", type=str, help="GitHub token for authentication")
    parser.add_argument("--repo", type=str, help="GitHub repository to scan (owner/repo)")
    parser.add_argument("--create-pr", action="store_true", help="Create a pull request with fixes")

    # Dashboard options
    parser.add_argument("--dashboard", action="store_true", help="Generate security metrics dashboard")

    # Custom AI server options
    parser.add_argument("--host", type=str, help="Custom AI server host")
    parser.add_argument("--port", type=int, help="Custom AI server port")
    parser.add_argument("--token", type=str, help="Custom AI server token")
    parser.add_argument("--endpoint", type=str, help="Custom AI server endpoint")

    return parser.parse_args()

def main():
    """Main entry point for the CLI."""
    args = parse_arguments()

    # Make sure environment variables are set for tokens
    import os
    import dotenv

    # Load environment variables from .env file
    dotenv.load_dotenv()

    # Ensure Hugging Face token is available
    if not os.environ.get("HUGGING_FACE_TOKEN") and not os.environ.get("HF_TOKEN"):
        print("Warning: No Hugging Face token found in environment variables.")
        print("SAST and SCA scanning may not work properly.")
        print("Please set HUGGING_FACE_TOKEN or HF_TOKEN in your .env file.")
    else:
        print(f"Using Hugging Face token from environment variables.")

    # Run the security pipeline
    results = run_security_pipeline(args)

    # Format and display the results
    formatted_results = format_pipeline_results(results)
    print(formatted_results)

    # Save results to a file
    with open("security_report.md", "w") as f:
        f.write(formatted_results)

    print(f"\nResults saved to security_report.md")

if __name__ == "__main__":
    main()
