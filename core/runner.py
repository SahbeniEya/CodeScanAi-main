"""
This is the runner of the codescan-ai CLI tool.
"""

import logging
import os
from typing import List, Dict, Any, Optional, Union, Mapping

from IPython.display import display_markdown

from core.code_scanner.code_scanner import CodeScanner
from core.utils.argument_parser import parse_arguments
from core.scanners.sast_scanner import Vulnerability
from core.scanners.unified_scanner import scan_all
from core.scanners.sca_scanner import SCAScanner
from core.providers.huggingface_provider import HuggingFaceProvider
from core.scanners.dast_scanner import scan_url
from core.fixers.fix_vulnerabilities import fix_vulnerabilities
# Import validators
from core.validation.fix_validator import FixValidator

# Define the EnhancedFixValidator class directly if import fails
try:
    from core.validation.enhanced_validator import EnhancedFixValidator  # type: ignore
except ImportError:
    # Fallback implementation
    class EnhancedFixValidator(FixValidator):
        """Fallback implementation of EnhancedFixValidator."""

        def enhanced_validate_fixes(self, vulnerabilities):
            """Fallback to regular validation."""
            return self.validate_fixes(vulnerabilities)

from core.github_integration.pr_creator import PRCreator
from core.dashboard.metrics_dashboard import SecurityMetrics, format_metrics_as_markdown
from core.utils.vulnerability_formatter import format_vulnerabilities_as_markdown, _remove_emoji

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def format_as_markdown(result):
    """
    Formats the scan result as Markdown.
    """
    output = "## Code Security Analysis Results\n"
    output += result
    return output


def run_security_pipeline(args) -> Dict[str, Union[None, str, List[Any], Dict[str, Any]]]:
    """
    Run the security pipeline based on the provided arguments.

    Args:
        args: Command-line arguments.

    Returns:
        Dict[str, Any]: Results of the security pipeline.
    """
    results: Dict[str, Union[None, str, List[Any], Dict[str, Any]]] = {
        "ai_scan": None,
        "sast_scan": None,
        "code_scan": None,
        "dependency_scan": None,
        "fixes": None,
        "validation": None,
        "pr": None,
        "dashboard": None,
        "error": None
    }

    # Initialize metrics
    metrics = SecurityMetrics()

    # If a GitHub repository is specified, clone it first
    # Store the original directory in case we need it later
    # original_directory = args.directory
    if args.repo and args.github_token:
        try:
            import tempfile
            from core.github_integration.github_auth import GitHubAuth

            # Create a temporary directory for the cloned repository
            temp_dir = tempfile.mkdtemp(prefix="codescan-")
            logging.info(f"Cloning repository {args.repo} to {temp_dir}...")

            # Clone the repository
            github_auth = GitHubAuth(token=args.github_token)
            github_auth.clone_repository(args.repo, temp_dir)

            # Update the directory to the cloned repository
            args.directory = temp_dir
            logging.info(f"Successfully cloned repository {args.repo} to {temp_dir}")
        except Exception as e:
            logging.error(f"Error cloning repository: {e}")
            results["error"] = f"Error cloning repository: {e}"
            return results

    # Step 1: Run AI-based scan
    logging.info("Running AI-based code scan...")
    ai_scan_result = CodeScanner(args).scan()
    results["ai_scan"] = ai_scan_result

    # Step 2: Run security scans as requested
    vulnerabilities = []

    # Run SAST scan if requested
    if hasattr(args, 'sast') and args.sast:
        logging.info("Running SAST scan...")
        try:
            # Get API keys
            nvd_api_key = getattr(args, 'nvd_api_key', None)
            huggingface_token = os.environ.get("HUGGING_FACE_TOKEN") or os.environ.get("HF_TOKEN")

            # Run unified scanner for all languages
            logging.info("Running unified scanner for all languages...")
            code_vulnerabilities = scan_all(
                args.directory,
                nvd_api_key=nvd_api_key,
                huggingface_token=huggingface_token
            )

            # Filter out SCA vulnerabilities from SAST results
            sast_vulnerabilities = []
            for vuln in code_vulnerabilities:
                # Only include SAST vulnerabilities (not SCA)
                if not (vuln.id.startswith("SCA-") or vuln.id.startswith("DEPENDENCY-")):
                    sast_vulnerabilities.append(vuln)

            vulnerabilities.extend(sast_vulnerabilities)
            results["code_scan"] = sast_vulnerabilities

            # If this is a SAST-only scan, make sure to clear any SCA vulnerabilities that might have been detected
            if not (hasattr(args, 'sca') and args.sca):
                # Remove any SCA vulnerabilities that might have been detected
                vulnerabilities = [v for v in vulnerabilities if not (v.id.startswith("SCA-") or v.id.startswith("DEPENDENCY-"))]

            logging.info(f"Found {len(sast_vulnerabilities)} code vulnerabilities")
        except Exception as e:
            logging.error(f"Error running SAST scan: {e}")
            results["code_scan"] = str(e)

    # Run SCA scan if requested
    if hasattr(args, 'sca') and args.sca:
        logging.info("Running Software Composition Analysis (SCA)...")
        try:
            # Get API keys
            nvd_api_key = getattr(args, 'nvd_api_key', None)
            # If not provided as an argument, try to get from environment variable
            if not nvd_api_key:
                nvd_api_key = os.environ.get("NVD_API_KEY")
                if nvd_api_key:
                    logging.info("Using NVD API key from environment variable")
                else:
                    logging.warning("No NVD API key provided. Some vulnerabilities may not be detected.")
            else:
                logging.info("Using NVD API key from command line arguments")

            huggingface_token = os.environ.get("HUGGING_FACE_TOKEN") or os.environ.get("HF_TOKEN")
            if huggingface_token:
                logging.info("Using Hugging Face token from environment variable")
            else:
                logging.warning("No Hugging Face token provided. AI-based detection will be limited.")

            # Run dependency scanner with Mistral model if specified
            logging.info("Scanning dependencies for vulnerabilities...")
            model_name = getattr(args, 'model', None) or "mistralai/Mistral-7B-Instruct-v0.3"

            # Always use the SCA scanner with the Mistral model for better detection
            logging.info(f"Using model for SCA scanning: {model_name}")
            scanner = SCAScanner(model_name=model_name)
            dependency_vulnerabilities = scanner.scan_directory(
                args.directory,
                nvd_api_key=nvd_api_key,
                huggingface_token=huggingface_token,
                use_ai_scan=True
            )
            vulnerabilities.extend(dependency_vulnerabilities)
            results["dependency_scan"] = dependency_vulnerabilities

            logging.info(f"Found {len(dependency_vulnerabilities)} dependency vulnerabilities")
        except Exception as e:
            logging.error(f"Error running SCA scan: {e}")
            results["dependency_scan"] = str(e)

    # Run DAST scan if requested
    if hasattr(args, 'dast') and args.dast:
        logging.info("Running Dynamic Application Security Testing (DAST)...")
        try:
            # Get target URL
            target_url = getattr(args, 'target_url', None)

            if not target_url:
                logging.error("No target URL provided for DAST scanning. Use --target-url parameter.")
                results["dast_scan"] = "Error: No target URL provided for DAST scanning. Use --target-url parameter."
            else:
                # Get ZAP path and API key
                zap_path = getattr(args, 'zap_path', None)
                zap_api_key = getattr(args, 'zap_api_key', None)
                use_basic_scanner = getattr(args, 'use_basic_scanner', True)  # Default to basic scanner

                # Run DAST scanner
                logging.info(f"Scanning URL for vulnerabilities: {target_url}")
                dast_vulnerabilities = scan_url(
                    target_url,
                    zap_path=zap_path,
                    api_key=zap_api_key,
                    use_basic_scanner=use_basic_scanner
                )
                vulnerabilities.extend(dast_vulnerabilities)
                results["dast_scan"] = dast_vulnerabilities

                logging.info(f"Found {len(dast_vulnerabilities)} DAST vulnerabilities")
        except Exception as e:
            logging.error(f"Error running DAST scan: {e}")
            results["dast_scan"] = f"Error running DAST scan: {str(e)}"

    # Store all vulnerabilities
    if vulnerabilities:
        # Store vulnerabilities in sast_scan for backward compatibility
        # but don't duplicate them in the report
        results["sast_scan"] = []

        # Record scan in metrics
        metrics.record_scan(vulnerabilities, args.repo)

        logging.info(f"Found {len(vulnerabilities)} vulnerabilities total")
    else:
        logging.info("No vulnerabilities found")
        results["sast_scan"] = []

    # Step 3: Generate fixes if requested
    if args.fix and vulnerabilities:
        logging.info("Generating fixes for vulnerabilities...")
        try:
            # First try to fix vulnerabilities using built-in fixers
            logging.info("Applying built-in fixers...")
            fixed_files = fix_vulnerabilities(vulnerabilities)

            # Count fixed files by type
            xml_fixed = len(fixed_files.get("xml", []))
            code_fixed = len(fixed_files.get("code", []))
            dependency_fixed = len(fixed_files.get("dependency", []))

            logging.info(f"Fixed {xml_fixed + code_fixed + dependency_fixed} files using built-in fixers")
            logging.info(f"  - XML files: {xml_fixed}")
            logging.info(f"  - Code files: {code_fixed}")
            logging.info(f"  - Dependency files: {dependency_fixed}")

            # For vulnerabilities that couldn't be fixed automatically, use AI-based fixes
            provider = HuggingFaceProvider(args.model)

            # Split vulnerabilities by type
            js_vulnerabilities = [v for v in vulnerabilities if v.file_path.endswith(('.js', '.jsx', '.ts', '.tsx'))]
            other_vulnerabilities = [v for v in vulnerabilities if not v.file_path.endswith(('.js', '.jsx', '.ts', '.tsx'))]

            # Generate fixes for JavaScript vulnerabilities
            if js_vulnerabilities:
                logging.info(f"Generating AI fixes for {len(js_vulnerabilities)} JavaScript vulnerabilities...")
                js_fixed_vulnerabilities = provider.generate_fixes_for_javascript_vulnerabilities(js_vulnerabilities)
            else:
                js_fixed_vulnerabilities = []

            # Generate fixes for other vulnerabilities
            if other_vulnerabilities:
                logging.info(f"Generating AI fixes for {len(other_vulnerabilities)} non-JavaScript vulnerabilities...")
                other_fixed_vulnerabilities = provider.generate_fixes_for_vulnerabilities(other_vulnerabilities)
            else:
                other_fixed_vulnerabilities = []

            # Combine the fixed vulnerabilities
            fixed_vulnerabilities = js_fixed_vulnerabilities + other_fixed_vulnerabilities
            results["fixes"] = {
                "ai_fixes": fixed_vulnerabilities,
                "built_in_fixes": fixed_files
            }

            # Count successful fixes
            successful_fixes = sum(1 for v in fixed_vulnerabilities if v.fix_suggestion)
            failed_fixes = len(vulnerabilities) - successful_fixes

            # Record fixes in metrics
            metrics.record_fixes(successful_fixes + xml_fixed + code_fixed + dependency_fixed, failed_fixes)

            logging.info(f"Generated {successful_fixes} AI fixes (failed: {failed_fixes})")
            logging.info(f"Total fixes: {successful_fixes + xml_fixed + code_fixed + dependency_fixed}")
        except Exception as e:
            logging.error(f"Error generating fixes: {e}")
            results["fixes"] = str(e)

    # Step 4: Validate fixes if requested
    if args.validate and vulnerabilities:
        logging.info("Validating fixes...")
        try:
            # Use the enhanced validator for more thorough validation
            validator = EnhancedFixValidator(args.directory)

            # Get vulnerabilities with AI-generated fixes
            ai_fixed_vulnerabilities = []
            if isinstance(results["fixes"], dict) and "ai_fixes" in results["fixes"]:
                ai_fixed_vulnerabilities = [v for v in results["fixes"]["ai_fixes"] if v.fix_suggestion]
            elif isinstance(results["fixes"], list):
                ai_fixed_vulnerabilities = [v for v in results["fixes"] if v.fix_suggestion]

            # Validate AI-generated fixes
            ai_validation_results = []
            if ai_fixed_vulnerabilities:
                ai_validation_results = validator.enhanced_validate_fixes(ai_fixed_vulnerabilities)

            # Validate built-in fixes by rescanning the files
            built_in_validation_results = []
            if isinstance(results["fixes"], dict) and "built_in_fixes" in results["fixes"]:
                built_in_fixes = results["fixes"]["built_in_fixes"]
                for fix_type, file_paths in built_in_fixes.items():
                    for file_path in file_paths:
                        # Check if the file still has vulnerabilities
                        if file_path.endswith(('.xml', '.svg', '.xsl', '.xslt', '.rss')):
                            from core.scanners.xml_scanner import scan_file
                            remaining_vulns = scan_file(file_path)
                            if not remaining_vulns:
                                built_in_validation_results.append({
                                    "success": True,
                                    "file_path": file_path,
                                    "fix_type": fix_type,
                                    "scanner_validation": {"success": True, "remaining_vulnerabilities": []}
                                })
                            else:
                                built_in_validation_results.append({
                                    "success": False,
                                    "file_path": file_path,
                                    "fix_type": fix_type,
                                    "scanner_validation": {"success": False, "remaining_vulnerabilities": remaining_vulns}
                                })

            # Combine validation results
            validation_results = {
                "ai_fixes": ai_validation_results,
                "built_in_fixes": built_in_validation_results
            }
            results["validation"] = validation_results

            # Count successful validations
            ai_successful = sum(1 for r in ai_validation_results if r["success"])
            built_in_successful = sum(1 for r in built_in_validation_results if r["success"])
            total_successful = ai_successful + built_in_successful
            total_validations = len(ai_validation_results) + len(built_in_validation_results)

            # Log detailed validation results
            logging.info(f"Validated {total_successful} fixes (failed: {total_validations - total_successful})")
            logging.info(f"  - AI fixes: {ai_successful} of {len(ai_validation_results)} successful")
            logging.info(f"  - Built-in fixes: {built_in_successful} of {len(built_in_validation_results)} successful")

            # Log AI fix validation details
            if ai_validation_results:
                logging.info("AI fix validation details:")
                for i, result in enumerate(ai_validation_results):
                    vuln = result["original_vulnerability"]
                    logging.info(f"  - {i+1}. {vuln.id} in {vuln.file_path}:{vuln.line_number}")
                    logging.info(f"    - Static analysis: {result['static_analysis']['passed'] if result['static_analysis'] else 'N/A'}")
                    logging.info(f"    - Test cases: {result['test_cases']['passed'] if result['test_cases'] else 'N/A'}")
                    logging.info(f"    - Scanner validation: {result['scanner_validation']['success'] if result['scanner_validation'] else 'N/A'}")

            # Log built-in fix validation details
            if built_in_validation_results:
                logging.info("Built-in fix validation details:")
                for i, result in enumerate(built_in_validation_results):
                    logging.info(f"  - {i+1}. {result['fix_type']} fix in {result['file_path']}")
                    logging.info(f"    - Success: {result['success']}")
                    if not result['success']:
                        logging.info(f"    - Remaining vulnerabilities: {len(result['scanner_validation']['remaining_vulnerabilities'])}")
        except Exception as e:
            logging.error(f"Error validating fixes: {e}")
            results["validation"] = str(e)

    # Step 5: Create PR if requested
    if args.create_pr and args.github_token and args.repo and vulnerabilities:
        logging.info("Creating pull request with fixes...")
        try:
            pr_creator = PRCreator(args.github_token, args.repo, args.directory)
            # Include all vulnerabilities, even those without fix suggestions
            pr_result = pr_creator.create_fix_pr(vulnerabilities)
            results["pr"] = pr_result

            # Record PR in metrics
            if pr_result["success"]:
                metrics.record_pr("open")
                logging.info(f"Created PR: {pr_result['pr']['url']}")
            else:
                logging.error(f"Failed to create PR: {pr_result['message']}")
        except Exception as e:
            logging.error(f"Error creating PR: {e}")
            results["pr"] = str(e)

    # Step 6: Show dashboard if requested
    if args.dashboard:
        logging.info("Generating security metrics dashboard...")
        try:
            dashboard_metrics = metrics.get_metrics_summary()
            results["dashboard"] = dashboard_metrics
        except Exception as e:
            logging.error(f"Error generating dashboard: {e}")
            results["dashboard"] = str(e)

    return results


def format_pipeline_results(results: Dict[str, Union[None, str, List[Any], Dict[str, Any]]]) -> str:
    """
    Format the results of the security pipeline as Markdown.

    Args:
        results (Dict[str, Any]): Results of the security pipeline.

    Returns:
        str: Markdown-formatted results.
    """
    # Check if this is a DAST-only scan
    is_dast_only = False
    if "dast_scan" in results and results["dast_scan"] and isinstance(results["dast_scan"], list) and results["dast_scan"]:
        # Check if other scan types are empty or not performed
        if (not results["code_scan"] or not isinstance(results["code_scan"], list) or not results["code_scan"]) and \
           (not results["dependency_scan"] or not isinstance(results["dependency_scan"], list) or not results["dependency_scan"]):
            is_dast_only = True
            logging.info("Detected DAST-only scan, formatting results accordingly")

    # Check if this is a SAST-only scan
    is_sast_only = False
    if results["code_scan"] and isinstance(results["code_scan"], list) and results["code_scan"]:
        # Check if other scan types are empty or not performed
        if (not "dast_scan" in results or not results["dast_scan"] or not isinstance(results["dast_scan"], list) or not results["dast_scan"]) and \
           (not results["dependency_scan"] or not isinstance(results["dependency_scan"], list) or not results["dependency_scan"]):
            is_sast_only = True
            logging.info("Detected SAST-only scan, formatting results accordingly")

    # Check if this is an SCA-only scan
    is_sca_only = False
    if results["dependency_scan"] and isinstance(results["dependency_scan"], list) and results["dependency_scan"]:
        # Check if other scan types are empty or not performed
        if (not "dast_scan" in results or not results["dast_scan"] or not isinstance(results["dast_scan"], list) or not results["dast_scan"]) and \
           (not results["code_scan"] or not isinstance(results["code_scan"], list) or not results["code_scan"]):
            is_sca_only = True
            logging.info("Detected SCA-only scan, formatting results accordingly")

    # If this is a DAST-only scan, only include DAST results
    if is_dast_only:
        dast_count = len(results["dast_scan"])

        # Count vulnerabilities by severity
        high_count = 0
        medium_count = 0
        low_count = 0

        for vuln in results["dast_scan"]:
            if vuln.severity == "HIGH":
                high_count += 1
            elif vuln.severity == "MEDIUM":
                medium_count += 1
            elif vuln.severity == "LOW":
                low_count += 1

        output = "# DAST Scan Results\n\n"

        # Add a structured summary section at the top with more details
        output += "## Summary\n\n"
        output += "### Vulnerability Metrics\n\n"
        output += f"- **Total Vulnerabilities**: {dast_count}\n"
        output += f"- **High Severity**: {high_count}\n"
        output += f"- **Medium Severity**: {medium_count}\n"
        output += f"- **Low Severity**: {low_count}\n\n"

        # Add vulnerability types section
        output += "### Vulnerability Types\n\n"

        # Count vulnerability types
        vuln_types = {}
        for vuln in results["dast_scan"]:
            vuln_type = vuln.id.split('-')[1] if '-' in vuln.id else vuln.id
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1

        # Add vulnerability types to summary
        for vuln_type, count in vuln_types.items():
            output += f"- **{vuln_type}**: {count}\n"

        output += "\n"

        # DAST scan results
        output += "## Dynamic Application Security Testing (DAST)\n\n"
        output += "The following vulnerabilities were detected during dynamic scanning of the web application:\n\n"

        # Make sure DAST vulnerabilities are properly formatted and displayed
        dast_output = format_vulnerabilities_as_markdown(results["dast_scan"])

        # Log the DAST output for debugging
        logging.info(f"DAST-only scan results: {len(results['dast_scan'])} vulnerabilities")
        logging.info(f"DAST-only output preview: {dast_output[:500]}...")

        output += dast_output + "\n\n"

        return output

    # If this is a SAST-only scan, only include SAST results
    if is_sast_only:
        sast_count = len(results["code_scan"])

        # Count vulnerabilities by severity
        high_count = 0
        medium_count = 0
        low_count = 0

        for vuln in results["code_scan"]:
            if vuln.severity == "HIGH":
                high_count += 1
            elif vuln.severity == "MEDIUM":
                medium_count += 1
            elif vuln.severity == "LOW":
                low_count += 1

        output = "# SAST Scan Results\n\n"

        # Add a structured summary section at the top with more details
        output += "## Summary\n\n"
        output += "### Vulnerability Metrics\n\n"
        output += f"- **Total Vulnerabilities**: {sast_count}\n"
        output += f"- **High Severity**: {high_count}\n"
        output += f"- **Medium Severity**: {medium_count}\n"
        output += f"- **Low Severity**: {low_count}\n\n"

        # Add vulnerability types section
        output += "### Vulnerability Types\n\n"

        # Count vulnerability types
        vuln_types = {}
        for vuln in results["code_scan"]:
            vuln_type = vuln.id.split('-')[1] if '-' in vuln.id else vuln.id
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1

        # Add vulnerability types to summary
        for vuln_type, count in vuln_types.items():
            output += f"- **{vuln_type}**: {count}\n"

        output += "\n"

        # SAST scan results
        output += "## Static Application Security Testing (SAST)\n\n"
        output += "The following vulnerabilities were detected during static analysis of the code:\n\n"

        # Make sure SAST vulnerabilities are properly formatted and displayed
        sast_output = format_vulnerabilities_as_markdown(results["code_scan"])

        # Log the SAST output for debugging
        logging.info(f"SAST-only scan results: {len(results['code_scan'])} vulnerabilities")
        logging.info(f"SAST-only output preview: {sast_output[:500]}...")

        output += sast_output + "\n\n"

        return output

    # If this is an SCA-only scan, only include SCA results
    if is_sca_only:
        sca_count = len(results["dependency_scan"])

        # Count vulnerabilities by severity
        high_count = 0
        medium_count = 0
        low_count = 0

        for vuln in results["dependency_scan"]:
            if vuln.severity == "HIGH":
                high_count += 1
            elif vuln.severity == "MEDIUM":
                medium_count += 1
            elif vuln.severity == "LOW":
                low_count += 1

        output = "# SCA Scan Results\n\n"

        # Add a structured summary section at the top with more details
        output += "## Summary\n\n"
        output += "### Vulnerability Metrics\n\n"
        output += f"- **Total Vulnerabilities**: {sca_count}\n"
        output += f"- **High Severity**: {high_count}\n"
        output += f"- **Medium Severity**: {medium_count}\n"
        output += f"- **Low Severity**: {low_count}\n\n"

        # Add vulnerability types section
        output += "### Vulnerability Types\n\n"

        # Count vulnerability types
        vuln_types = {}
        for vuln in results["dependency_scan"]:
            vuln_type = vuln.id.split('-')[1] if '-' in vuln.id else vuln.id
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1

        # Add vulnerability types to summary
        for vuln_type, count in vuln_types.items():
            output += f"- **{vuln_type}**: {count}\n"

        output += "\n"

        # SCA scan results
        output += "## Software Composition Analysis (SCA)\n\n"
        output += "The following vulnerabilities were detected in dependencies:\n\n"

        # Make sure SCA vulnerabilities are properly formatted and displayed
        sca_output = format_vulnerabilities_as_markdown(results["dependency_scan"])

        # Log the SCA output for debugging
        logging.info(f"SCA-only scan results: {len(results['dependency_scan'])} vulnerabilities")
        logging.info(f"SCA-only output preview: {sca_output[:500]}...")

        output += sca_output + "\n\n"

        return output

    # For non-DAST-only scans, use the original formatting
    output = "# Security Pipeline Results\n\n"

    # Add a structured summary section at the top
    output += "## Summary\n\n"

    # Count vulnerabilities by type
    sast_count = len(results["code_scan"]) if isinstance(results["code_scan"], list) else 0
    dependency_count = len(results["dependency_scan"]) if isinstance(results["dependency_scan"], list) else 0
    dast_count = len(results["dast_scan"]) if "dast_scan" in results and isinstance(results["dast_scan"], list) else 0
    vuln_count = sast_count + dependency_count + dast_count

    # Count fixes
    fix_count = 0
    if results["fixes"] and isinstance(results["fixes"], dict):
        # Count AI fixes
        if "ai_fixes" in results["fixes"] and isinstance(results["fixes"]["ai_fixes"], list):
            fix_count += sum(1 for v in results["fixes"]["ai_fixes"] if hasattr(v, 'fix_suggestion') and v.fix_suggestion)

        # Count built-in fixes
        if "built_in_fixes" in results["fixes"] and isinstance(results["fixes"]["built_in_fixes"], dict):
            fix_count += sum(len(files) for files in results["fixes"]["built_in_fixes"].values())
    elif results["fixes"] and isinstance(results["fixes"], list):
        fix_count = sum(1 for v in results["fixes"] if hasattr(v, 'fix_suggestion') and v.fix_suggestion)

    # Count validations
    validation_count = 0
    if results["validation"] and isinstance(results["validation"], dict):
        # Count AI fix validations
        if "ai_fixes" in results["validation"] and isinstance(results["validation"]["ai_fixes"], list):
            validation_count += sum(1 for r in results["validation"]["ai_fixes"] if r.get("success", False))

        # Count built-in fix validations
        if "built_in_fixes" in results["validation"] and isinstance(results["validation"]["built_in_fixes"], list):
            validation_count += sum(1 for r in results["validation"]["built_in_fixes"] if r.get("success", False))
    elif results["validation"] and isinstance(results["validation"], list):
        validation_count = sum(1 for r in results["validation"] if r.get("success", False))

    # Add summary table
    output += "| Category | Count |\n"
    output += "|----------|-------:|\n"
    output += f"| Vulnerabilities | {vuln_count} |\n"
    output += f"| Fixes Generated | {fix_count} |\n"
    output += f"| Fixes Validated | {validation_count} |\n\n"

    # Add PR status
    if results["pr"]:
        if isinstance(results["pr"], dict) and results["pr"].get("success"):
            output += "**Pull Request:** Created successfully\n\n"
        else:
            output += "**Pull Request:** Failed to create\n\n"

    # AI scan results
    if results["ai_scan"]:
        output += "## AI-Based Code Scan\n\n"
        if isinstance(results["ai_scan"], str):
            output += results["ai_scan"] + "\n\n"
        else:
            output += str(results["ai_scan"]) + "\n\n"

    # SAST scan results
    if results["sast_scan"]:
        output += "## SAST Scan\n\n"
        if isinstance(results["sast_scan"], list):
            output += format_vulnerabilities_as_markdown(results["sast_scan"]) + "\n\n"
        elif isinstance(results["sast_scan"], str):
            output += results["sast_scan"] + "\n\n"
        else:
            output += str(results["sast_scan"]) + "\n\n"

    # Code scan results
    if results["code_scan"] and isinstance(results["code_scan"], list) and results["code_scan"]:
        output += "## Code Security Analysis\n\n"
        output += format_vulnerabilities_as_markdown(results["code_scan"]) + "\n\n"

    # Dependency scan results - only include if SCA scanning was performed
    if results["dependency_scan"] and isinstance(results["dependency_scan"], list) and results["dependency_scan"]:
        # Check if this was a SAST-only scan by looking for SCA scan log message
        sast_only = "Running SAST scan..." in output and "Running Software Composition Analysis (SCA)..." not in output

        # Only include dependency scan results if this wasn't a SAST-only scan
        if not sast_only:
            output += "## Dependency Security Analysis\n\n"
            output += format_vulnerabilities_as_markdown(results["dependency_scan"]) + "\n\n"

    # DAST scan results
    if "dast_scan" in results and results["dast_scan"] and isinstance(results["dast_scan"], list) and results["dast_scan"]:
        output += "## Dynamic Application Security Testing (DAST)\n\n"
        output += "The following vulnerabilities were detected during dynamic scanning of the web application:\n\n"

        # Make sure DAST vulnerabilities are properly formatted and displayed
        dast_output = format_vulnerabilities_as_markdown(results["dast_scan"])

        # Log the DAST output for debugging
        logging.info(f"DAST scan results: {len(results['dast_scan'])} vulnerabilities")
        logging.info(f"DAST output preview: {dast_output[:500]}...")

        output += dast_output + "\n\n"

    # Fix results
    if results["fixes"]:
        output += "## Generated Fixes\n\n"
        if isinstance(results["fixes"], dict):
            # Built-in fixes
            if "built_in_fixes" in results["fixes"] and isinstance(results["fixes"]["built_in_fixes"], dict):
                built_in_fixes = results["fixes"]["built_in_fixes"]
                total_built_in = sum(len(files) for files in built_in_fixes.values())

                if total_built_in > 0:
                    output += "### Built-in Fixes\n\n"
                    output += f"Applied {total_built_in} built-in fixes to vulnerable files.\n\n"

                    # XML fixes
                    if "xml" in built_in_fixes and built_in_fixes["xml"]:
                        output += "#### XML Fixes\n\n"
                        output += f"Fixed {len(built_in_fixes['xml'])} XML files with XXE or XSLT vulnerabilities:\n\n"
                        for file_path in built_in_fixes["xml"]:
                            output += f"- {file_path}\n"
                        output += "\n"

                    # Code fixes
                    if "code" in built_in_fixes and built_in_fixes["code"]:
                        output += "#### Code Fixes\n\n"
                        output += f"Fixed {len(built_in_fixes['code'])} code files with security vulnerabilities:\n\n"
                        for file_path in built_in_fixes["code"]:
                            output += f"- {file_path}\n"
                        output += "\n"

                    # Dependency fixes
                    if "dependency" in built_in_fixes and built_in_fixes["dependency"]:
                        output += "#### Dependency Fixes\n\n"
                        output += f"Fixed {len(built_in_fixes['dependency'])} dependency files with security vulnerabilities:\n\n"
                        for file_path in built_in_fixes["dependency"]:
                            output += f"- {file_path}\n"
                        output += "\n"

            # AI-based fixes
            if "ai_fixes" in results["fixes"] and isinstance(results["fixes"]["ai_fixes"], list):
                ai_fixes = results["fixes"]["ai_fixes"]
                fixed_count = sum(1 for v in ai_fixes if v.fix_suggestion)
                total_count = len(ai_fixes)

                if total_count > 0:
                    output += "### AI-Generated Fixes\n\n"
                    output += f"Generated AI fixes for {fixed_count} out of {total_count} vulnerabilities.\n\n"
        elif isinstance(results["fixes"], list):
            fixed_count = sum(1 for v in results["fixes"] if v.fix_suggestion)
            total_count = len(results["fixes"])
            output += f"Generated fixes for {fixed_count} out of {total_count} vulnerabilities.\n\n"
        elif isinstance(results["fixes"], str):
            output += results["fixes"] + "\n\n"
        else:
            output += str(results["fixes"]) + "\n\n"

    # Validation results
    if results["validation"]:
        output += "## Fix Validation\n\n"

        if isinstance(results["validation"], dict):
            # Count validations
            ai_validation_count = 0
            ai_total_count = 0
            if "ai_fixes" in results["validation"] and isinstance(results["validation"]["ai_fixes"], list):
                ai_validation_count = sum(1 for r in results["validation"]["ai_fixes"] if r["success"])
                ai_total_count = len(results["validation"]["ai_fixes"])

            built_in_validation_count = 0
            built_in_total_count = 0
            if "built_in_fixes" in results["validation"] and isinstance(results["validation"]["built_in_fixes"], list):
                built_in_validation_count = sum(1 for r in results["validation"]["built_in_fixes"] if r["success"])
                built_in_total_count = len(results["validation"]["built_in_fixes"])

            total_validation_count = ai_validation_count + built_in_validation_count
            total_count = ai_total_count + built_in_total_count

            output += f"Successfully validated {total_validation_count} out of {total_count} fixes.\n\n"

            # Built-in fix validation results
            if "built_in_fixes" in results["validation"] and isinstance(results["validation"]["built_in_fixes"], list) and results["validation"]["built_in_fixes"]:
                built_in_fixes = results["validation"]["built_in_fixes"]

                output += "### Built-in Fix Validation\n\n"
                output += f"Successfully validated {built_in_validation_count} out of {built_in_total_count} built-in fixes.\n\n"

                # Add detailed validation results
                output += "#### Validation Details\n\n"
                for i, result in enumerate(built_in_fixes):
                    output += f"**{i+1}. {result['fix_type'].upper()} fix in {result['file_path']}**\n\n"
                    output += f"**Result:** {'[CHECK] Passed' if result['success'] else '[X] Failed'}\n\n"

                    # Scanner validation results
                    if result["scanner_validation"]:
                        scanner = result["scanner_validation"]
                        if "remaining_vulnerabilities" in scanner and scanner["remaining_vulnerabilities"]:
                            output += "*Remaining Vulnerabilities:*\n"
                            for vuln in scanner["remaining_vulnerabilities"]:
                                output += f"- {vuln.id} in {vuln.file_path}:{vuln.line_number}\n"
                            output += "\n"

                    output += "---\n\n"

            # AI fix validation results
            if "ai_fixes" in results["validation"] and isinstance(results["validation"]["ai_fixes"], list) and results["validation"]["ai_fixes"]:
                ai_fixes = results["validation"]["ai_fixes"]

                output += "### AI-Generated Fix Validation\n\n"
                output += f"Successfully validated {ai_validation_count} out of {ai_total_count} AI-generated fixes.\n\n"

                # Add detailed validation results
                output += "#### Validation Details\n\n"
                for i, result in enumerate(ai_fixes):
                    vuln = result["original_vulnerability"]
                    output += f"**{i+1}. {vuln.id} in {vuln.file_path}:{vuln.line_number}**\n\n"

                    # Static analysis results
                    if result["static_analysis"]:
                        static_analysis = result["static_analysis"]
                        output += f"**Static Analysis:** {'[CHECK] Passed' if static_analysis['passed'] else '[X] Failed'}\n\n"
                        if "details" in static_analysis and static_analysis["details"]:
                            output += "*Details:*\n"
                            for detail in static_analysis["details"]:
                                output += f"- {_remove_emoji(detail)}\n"
                            output += "\n"

                    # Test case results
                    if result["test_cases"]:
                        test_cases = result["test_cases"]
                        output += f"**Test Cases:** {'[CHECK] Passed' if test_cases['passed'] else '[X] Failed'}\n\n"
                        if "test_results" in test_cases and test_cases["test_results"]:
                            output += "*Test Results:*\n"
                            output += "| Test Case | Input | Expected | Actual | Result |\n"
                            output += "|-----------|-------|----------|--------|--------|\n"
                            for test in test_cases["test_results"]:
                                output += f"| {_remove_emoji(test['test_case'])} | `{_remove_emoji(test['input'])}` | {_remove_emoji(test['expected_safe'])} | {_remove_emoji(test['actual_safe'])} | {'[CHECK]' if test['passed'] else '[X]'} |\n"
                            output += "\n"

                    # Scanner validation results
                    if result["scanner_validation"]:
                        scanner = result["scanner_validation"]
                        output += f"**Scanner Validation:** {'[CHECK] Passed' if scanner['success'] else '[X] Failed'}\n\n"
                        if "remaining_vulnerabilities" in scanner and scanner["remaining_vulnerabilities"]:
                            output += "*Remaining Vulnerabilities:*\n"
                            for vuln in scanner["remaining_vulnerabilities"]:
                                output += f"- {vuln.id} in {vuln.file_path}:{vuln.line_number}\n"
                            output += "\n"

                    output += "---\n\n"

        elif isinstance(results["validation"], list):
            successful_count = sum(1 for r in results["validation"] if r["success"])
            total_count = len(results["validation"])
            output += f"Successfully validated {successful_count} out of {total_count} fixes.\n\n"

            # Add detailed validation results
            output += "### Validation Details\n\n"
            for i, result in enumerate(results["validation"]):
                vuln = result["original_vulnerability"]
                output += f"#### {i+1}. {vuln.id} in {vuln.file_path}:{vuln.line_number}\n\n"

                # Static analysis results
                if result["static_analysis"]:
                    static_analysis = result["static_analysis"]
                    output += f"**Static Analysis:** {'[CHECK] Passed' if static_analysis['passed'] else '[X] Failed'}\n\n"
                    if "details" in static_analysis and static_analysis["details"]:
                        output += "*Details:*\n"
                        for detail in static_analysis["details"]:
                            output += f"- {_remove_emoji(detail)}\n"
                        output += "\n"

                # Test case results
                if result["test_cases"]:
                    test_cases = result["test_cases"]
                    output += f"**Test Cases:** {'[CHECK] Passed' if test_cases['passed'] else '[X] Failed'}\n\n"
                    if "test_results" in test_cases and test_cases["test_results"]:
                        output += "*Test Results:*\n"
                        output += "| Test Case | Input | Expected | Actual | Result |\n"
                        output += "|-----------|-------|----------|--------|--------|\n"
                        for test in test_cases["test_results"]:
                            output += f"| {_remove_emoji(test['test_case'])} | `{_remove_emoji(test['input'])}` | {_remove_emoji(test['expected_safe'])} | {_remove_emoji(test['actual_safe'])} | {'[CHECK]' if test['passed'] else '[X]'} |\n"
                        output += "\n"

                # Scanner validation results
                if result["scanner_validation"]:
                    scanner = result["scanner_validation"]
                    output += f"**Scanner Validation:** {'[CHECK] Passed' if scanner['success'] else '[X] Failed'}\n\n"
                    if "remaining_vulnerabilities" in scanner and scanner["remaining_vulnerabilities"]:
                        output += "*Remaining Vulnerabilities:*\n"
                        for vuln in scanner["remaining_vulnerabilities"]:
                            output += f"- {vuln.id} in {vuln.file_path}:{vuln.line_number}\n"
                        output += "\n"

                output += "---\n\n"
        elif isinstance(results["validation"], str):
            output += results["validation"] + "\n\n"
        else:
            output += str(results["validation"]) + "\n\n"

    # PR results
    if results["pr"]:
        output += "## Pull Request\n\n"
        if isinstance(results["pr"], dict) and results["pr"].get("success"):
            pr_info = results["pr"]["pr"]
            output += f"Created PR #{pr_info['number']}: [{pr_info['title']}]({pr_info['url']})\n\n"
        else:
            output += f"Failed to create PR: {results['pr']}\n\n"

    # Dashboard results
    if results["dashboard"]:
        output += "## Security Metrics Dashboard\n\n"
        if isinstance(results["dashboard"], dict):
            output += format_metrics_as_markdown(results["dashboard"]) + "\n\n"
        elif isinstance(results["dashboard"], str):
            output += results["dashboard"] + "\n\n"
        else:
            output += str(results["dashboard"]) + "\n\n"

    return output


def main():
    """
    Main entry point for the CLI. Parses arguments, runs the security pipeline,
    and displays the results.
    """
    args = parse_arguments()

    # Run the security pipeline
    results = run_security_pipeline(args)

    # Format and display the results
    formatted_results = format_pipeline_results(results)
    display_markdown(formatted_results)


if __name__ == "__main__":
    main()
