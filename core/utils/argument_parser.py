"""
This module provides util methods for understanding and parsing the arguments sent by user in the CLI.
"""

import argparse


def parse_arguments():
    """
    Parses command-line arguments for the AI-based code scanner.
    """
    parser = argparse.ArgumentParser(
        description="A CLI tool for powered by GenAI to access vulnerability of codebases and provide suggestions."
    )

    parser.add_argument(
        "--provider",
        type=str,
        default="huggingface",
        choices=["openai", "gemini", "huggingface", "custom"],
        help="Select the AI provider (default: huggingface)",
    )
    parser.add_argument(
        "--directory",
        type=str,
        default=".",
        help="Directory to scan (defaults to root)",
    )
    parser.add_argument(
        "--model",
        type=str,
        help="AI model to use (optional, defaults vary by provider. See [gemini: gemini-pro, openai: gpt-4o-mini, huggingface: HuggingFaceH4/zephyr-7b-beta])",
    )
    parser.add_argument(
        "--changes_only",
        action="store_true",
        help="Scan only changed files in a git repository",
    )

    # Additional arguments for PR scanning
    parser.add_argument(
        "--repo", type=str, help="GitHub repository in the format 'owner/repo'"
    )
    parser.add_argument("--pr_number", type=int, help="Pull request number")
    parser.add_argument("--github_token", help="GitHub API token")

    # Additional arguments for security scanning and fixing
    parser.add_argument(
        "--sast", action="store_true", help="Perform SAST scanning (Static Application Security Testing)"
    )
    parser.add_argument(
        "--sca", action="store_true", help="Perform SCA scanning (Software Composition Analysis)"
    )
    parser.add_argument(
        "--dast", action="store_true", help="Perform DAST scanning (Dynamic Application Security Testing)"
    )
    parser.add_argument(
        "--target-url", type=str, help="Target URL for DAST scanning"
    )
    parser.add_argument(
        "--zap-path", type=str, help="Path to ZAP installation for DAST scanning"
    )
    parser.add_argument(
        "--zap-api-key", type=str, help="API key for ZAP"
    )
    parser.add_argument(
        "--use-basic-scanner", action="store_true", help="Use basic scanner instead of ZAP for DAST"
    )
    parser.add_argument(
        "--fix", action="store_true", help="Generate fixes for vulnerabilities"
    )
    parser.add_argument(
        "--validate", action="store_true", help="Validate generated fixes"
    )
    parser.add_argument(
        "--create-pr", action="store_true", help="Create a pull request with fixes"
    )
    parser.add_argument(
        "--dashboard", action="store_true", help="Show security metrics dashboard"
    )

    # Additional arguments for custom provider
    parser.add_argument(
        "--host", type=str, help="Custom AI server host (e.g., http://localhost)"
    )
    parser.add_argument("--port", type=int, help="Custom AI server port (e.g., 5000)")
    parser.add_argument(
        "--token", type=str, help="Token for authenticating with the custom AI server"
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default="/api/v1/scan",
        help="API endpoint for the custom server",
    )

    return parser.parse_args()
