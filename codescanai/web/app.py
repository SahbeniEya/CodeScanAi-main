"""
This module contains the Flask application for CodeScanAI.
"""

import os
import logging
import json
import re
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_bootstrap import Bootstrap
# Import with type ignore to suppress type checking errors
from wtforms import StringField, SelectField, BooleanField, SubmitField  # type: ignore
from wtforms.validators import DataRequired, Optional

from core.runner import run_security_pipeline, format_pipeline_results
from core.dashboard.metrics_dashboard import SecurityMetrics
from core.github_integration.github_auth import GitHubAuth
from core.github_integration.pr_creator import PRCreator
import tempfile
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Create Flask application
app = Flask(__name__,
           template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
           static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing-only')
app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'flatly'

# Initialize extensions
csrf = CSRFProtect(app)
bootstrap = Bootstrap(app)

# Define forms
class ScanForm(FlaskForm):
    """Form for scanning code."""
    provider = SelectField('AI Provider', choices=[
        ('huggingface', 'Hugging Face'),
        ('openai', 'OpenAI'),
        ('gemini', 'Google Gemini'),
        ('custom', 'Custom AI Server')
    ], default='huggingface', validators=[DataRequired()])

    model = StringField('Model', default='mistralai/Mistral-7B-Instruct-v0.3', validators=[Optional()])

    directory = StringField('Directory', default='.', validators=[DataRequired()])

    changes_only = BooleanField('Scan Only Changed Files', default=False)  # type: ignore

    scan_type = SelectField('Scan Type', choices=[
        ('all', 'All (SAST, SCA & DAST)'),
        ('both', 'Both SAST & SCA'),
        ('sast', 'SAST Only (Static Application Security Testing)'),
        ('sca', 'SCA Only (Software Composition Analysis)'),
        ('dast', 'DAST Only (Dynamic Application Security Testing)')
    ], default='both', validators=[DataRequired()])

    sast = BooleanField('Perform SAST Scanning', default=True)  # type: ignore

    fix = BooleanField('Generate Fixes', default=False)  # type: ignore

    validate = BooleanField('Validate Fixes', default=False)  # type: ignore

    create_pr = BooleanField('Create Pull Request', default=False)  # type: ignore

    dashboard = BooleanField('Show Dashboard', default=True)  # type: ignore

    github_token = StringField('GitHub Token', validators=[Optional()])

    nvd_api_key = StringField('NVD API Key (for SCA scanning)', validators=[Optional()],
                             description='API key for the National Vulnerability Database')

    huggingface_token = StringField('Hugging Face API Key', validators=[Optional()],
                                  description='API key for Hugging Face (required for Llama models)')

    # DAST fields
    target_url = StringField('Target URL (for DAST scanning)', validators=[Optional()],
                           description='URL of the web application to scan dynamically')

    zap_path = StringField('ZAP Path (for DAST scanning)', validators=[Optional()],
                         description='Path to ZAP installation (leave empty for auto-detection)')

    zap_api_key = StringField('ZAP API Key (for DAST scanning)', validators=[Optional()],
                            description='API key for ZAP (leave empty to generate a random one)')

    repo = StringField('GitHub Repository (owner/repo)', validators=[Optional()])

    submit = SubmitField('Scan')


class GitHubForm(FlaskForm):
    """Form for GitHub authentication."""
    token = StringField('GitHub Token', validators=[DataRequired()])
    submit = SubmitField('Login')


# Define routes
@app.route('/')
def index():
    """Render the index page."""
    return render_template('index.html')


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Render the scan page and handle form submission."""
    form = ScanForm()

    # Check if repo parameter is provided in the URL
    repo_param = request.args.get('repo')
    if repo_param:
        form.repo.data = repo_param

    if form.validate_on_submit():
        # Determine SAST, SCA, and DAST settings based on scan_type
        perform_sast = form.scan_type.data in ['all', 'both', 'sast']
        perform_sca = form.scan_type.data in ['all', 'both', 'sca']
        perform_dast = form.scan_type.data in ['all', 'dast']

        # Store the scan type in the session for later use
        session['scan_type'] = form.scan_type.data
        logging.info(f"Scan type selected: {form.scan_type.data}")

        # If this is a DAST scan, store the target URL in the session
        if form.scan_type.data == 'dast':
            session['target_url'] = form.target_url.data
            logging.info(f"DAST scan target URL: {form.target_url.data}")

        # Create a dictionary of arguments
        args_dict = {
            'provider': form.provider.data,
            'model': form.model.data if form.model.data else None,
            'directory': form.directory.data,
            'changes_only': form.changes_only.data,
            'sast': perform_sast,
            'sca': perform_sca,
            'dast': perform_dast,
            'target_url': form.target_url.data if form.target_url.data else None,
            'zap_path': form.zap_path.data if form.zap_path.data else None,
            'zap_api_key': form.zap_api_key.data if form.zap_api_key.data else None,
            'fix': form.fix.data,
            'validate': form.validate.data,
            'create_pr': form.create_pr.data,
            'dashboard': form.dashboard.data,
            'github_token': form.github_token.data if form.github_token.data else session.get('github_token'),
            'nvd_api_key': form.nvd_api_key.data if form.nvd_api_key.data else os.environ.get("NVD_API_KEY"),
            'repo': form.repo.data if form.repo.data else None,
            'pr_number': None,
            'host': None,
            'port': None,
            'token': None,
            'endpoint': None
        }

        # If NVD API key is provided, set it as an environment variable for the scanner
        if form.nvd_api_key.data:
            os.environ['NVD_API_KEY'] = form.nvd_api_key.data

        # If Hugging Face token is provided, set it as an environment variable for the scanner
        if form.huggingface_token.data:
            os.environ['HF_TOKEN'] = form.huggingface_token.data
            os.environ['HUGGING_FACE_TOKEN'] = form.huggingface_token.data

        # Convert the dictionary to an object
        class Args:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)

        args = Args(**args_dict)

        # Run the security pipeline
        results = run_security_pipeline(args)

        # Format the results
        formatted_results = format_pipeline_results(results)

        # Log the formatted results for debugging
        logging.info(f"Formatted results length: {len(formatted_results)}")
        logging.info(f"Formatted results preview: {formatted_results[:500]}...")

        # Check if DAST scan was performed and log the results
        if perform_dast:
            logging.info("DAST scan was performed, checking for DAST vulnerabilities in results")
            dast_pattern = r'DAST-[A-Z0-9-]+:'
            dast_matches = re.findall(dast_pattern, formatted_results)
            logging.info(f"Found {len(dast_matches)} DAST vulnerability patterns in results")

            # Log the first few DAST vulnerabilities found
            for i, match in enumerate(dast_matches[:5]):
                logging.info(f"DAST vulnerability {i+1}: {match}")

        # Store the results in the session
        session['scan_results'] = formatted_results

        # Redirect to the results page
        return redirect(url_for('results'))

    return render_template('scan.html', form=form)


@app.route('/results')
def results():
    """Render the results page."""
    # Get the results from the session
    formatted_results = session.get('scan_results', None)
    scan_type = session.get('scan_type', None)

    if not formatted_results:
        # Instead of redirecting, render the results page with a message
        return render_template('results.html', results=None, no_results=True, scan_type=scan_type)

    # Check if this was a DAST-only scan
    is_dast_only = scan_type == 'dast'

    # Check if this was a SAST-only scan
    is_sast_only = scan_type == 'sast'

    # Check if this was an SCA-only scan
    is_sca_only = scan_type == 'sca'

    # If this is a DAST-only scan, we need to make sure only DAST vulnerabilities are displayed
    if is_dast_only:
        logging.info("DAST-only scan detected, checking for DAST vulnerabilities in results")

        # Check if there are DAST vulnerabilities in the results
        dast_pattern = r'DAST-[A-Z0-9-]+:'
        dast_matches = re.findall(dast_pattern, formatted_results)
        logging.info(f"Found {len(dast_matches)} DAST vulnerability patterns in results")

        # If we found DAST vulnerabilities, make sure they're properly displayed
        if dast_matches:
            # Extract the DAST section from the results
            dast_section_match = re.search(r'## Dynamic Application Security Testing \(DAST\)([\s\S]*?)(?=##|$)', formatted_results)
            if dast_section_match:
                dast_section = dast_section_match.group(0)
                logging.info(f"Found DAST section with length: {len(dast_section)}")

                # Create a new formatted results with only the DAST section
                # We'll keep the original format as it should now be properly formatted by runner.py
                # Just make sure to add the scan target information
                if "**Scan Target**" not in formatted_results:
                    # Find the summary section
                    summary_section_match = re.search(r'## Summary\n\n', formatted_results)
                    if summary_section_match:
                        # Insert the scan target after the summary heading
                        insert_pos = summary_section_match.end()
                        formatted_results = formatted_results[:insert_pos] + f"**Scan Target**: {session.get('target_url', 'Unknown')}\n\n" + formatted_results[insert_pos:]
                    else:
                        # If no summary section, just add it at the top
                        formatted_results = f"# DAST Scan Results\n\n## Summary\n\n**Scan Target**: {session.get('target_url', 'Unknown')}\n\n" + formatted_results

                logging.info(f"Created new formatted results with only DAST vulnerabilities, length: {len(formatted_results)}")

    # If this is a SAST-only scan, we need to make sure only SAST vulnerabilities are displayed
    elif is_sast_only:
        logging.info("SAST-only scan detected, checking for SAST vulnerabilities in results")

        # Check if there are SAST vulnerabilities in the results
        sast_pattern = r'(BANDIT|JAVA|PHP|JS|RUBY|GO)-[A-Z0-9-]+:'
        sast_matches = re.findall(sast_pattern, formatted_results)
        logging.info(f"Found {len(sast_matches)} SAST vulnerability patterns in results")

        # If we found SAST vulnerabilities, make sure they're properly displayed
        if sast_matches:
            # Extract the SAST section from the results
            sast_section_match = re.search(r'## Static Application Security Testing \(SAST\)([\s\S]*?)(?=##|$)', formatted_results)
            if sast_section_match:
                sast_section = sast_section_match.group(0)
                logging.info(f"Found SAST section with length: {len(sast_section)}")

                # We'll keep the original format as it should now be properly formatted by runner.py
                logging.info(f"Using SAST-only formatted results, length: {len(formatted_results)}")

    # If this is an SCA-only scan, we need to make sure only SCA vulnerabilities are displayed
    elif is_sca_only:
        logging.info("SCA-only scan detected, checking for SCA vulnerabilities in results")

        # Check if there are SCA vulnerabilities in the results
        sca_pattern = r'(SCA|CVE)-[A-Z0-9-]+:'
        sca_matches = re.findall(sca_pattern, formatted_results)
        logging.info(f"Found {len(sca_matches)} SCA vulnerability patterns in results")

        # If we found SCA vulnerabilities, make sure they're properly displayed
        if sca_matches:
            # Extract the SCA section from the results
            sca_section_match = re.search(r'## Software Composition Analysis \(SCA\)([\s\S]*?)(?=##|$)', formatted_results)
            if sca_section_match:
                sca_section = sca_section_match.group(0)
                logging.info(f"Found SCA section with length: {len(sca_section)}")

                # We'll keep the original format as it should now be properly formatted by runner.py
                logging.info(f"Using SCA-only formatted results, length: {len(formatted_results)}")

    # Store the modified results in the session
    session['scan_results'] = formatted_results

    return render_template('results.html', results=formatted_results, no_results=False, scan_type=scan_type,
                           is_dast_only=is_dast_only, is_sast_only=is_sast_only, is_sca_only=is_sca_only)


@app.route('/dashboard')
def dashboard():
    """Render the dashboard page."""
    # Get the metrics
    metrics = SecurityMetrics().get_metrics_summary()

    # Get the latest scan results from the session
    formatted_results = session.get('scan_results', None)

    # If there are scan results, update the metrics with the latest scan results
    if formatted_results:
        try:
            # Extract vulnerability counts from the formatted results
            high_match = re.search(r'\*\*High Severity\*\*: (\d+)', formatted_results)
            medium_match = re.search(r'\*\*Medium Severity\*\*: (\d+)', formatted_results)
            low_match = re.search(r'\*\*Low Severity\*\*: (\d+)', formatted_results)
            total_match = re.search(r'\*\*Total\*\*: (\d+)', formatted_results)

            # Extract fix metrics from the formatted results
            fixes_attempted_match = re.search(r'\*\*Total Fixes Attempted\*\*: (\d+)', formatted_results)
            successful_fixes_match = re.search(r'\*\*Successful Fixes\*\*: (\d+)', formatted_results)

            # Update the metrics with the latest scan results
            if high_match:
                metrics['vulnerabilities']['by_severity']['HIGH'] = int(high_match.group(1))
            if medium_match:
                metrics['vulnerabilities']['by_severity']['MEDIUM'] = int(medium_match.group(1))
            if low_match:
                metrics['vulnerabilities']['by_severity']['LOW'] = int(low_match.group(1))
            if total_match:
                metrics['vulnerabilities']['total'] = int(total_match.group(1))

            # Update fix metrics
            if fixes_attempted_match:
                metrics['fixes']['total'] = int(fixes_attempted_match.group(1))
            if successful_fixes_match:
                metrics['fixes']['successful'] = int(successful_fixes_match.group(1))

            # Calculate success rate
            if metrics['fixes']['total'] > 0:
                metrics['fixes']['success_rate'] = metrics['fixes']['successful'] / metrics['fixes']['total']
            else:
                metrics['fixes']['success_rate'] = 0

            # If no vulnerabilities were found in the regex, try to count them from the PR format
            if not total_match:
                # Look for the PR format pattern
                pr_fix_pattern = re.findall(r'Fix for ([^\n]+) in ([^:]+):(\d+)', formatted_results)
                if pr_fix_pattern:
                    metrics['vulnerabilities']['total'] = len(pr_fix_pattern)
                    # Count high, medium, and low severity vulnerabilities
                    high_count = sum(1 for match in pr_fix_pattern if 'HIGH' in match[0])
                    medium_count = sum(1 for match in pr_fix_pattern if 'MEDIUM' in match[0])
                    low_count = sum(1 for match in pr_fix_pattern if 'LOW' in match[0])

                    metrics['vulnerabilities']['by_severity']['HIGH'] = high_count
                    metrics['vulnerabilities']['by_severity']['MEDIUM'] = medium_count
                    metrics['vulnerabilities']['by_severity']['LOW'] = low_count
        except Exception as e:
            logging.error(f"Error updating metrics with latest scan results: {e}")

    return render_template('dashboard.html', metrics=metrics)


@app.route('/github', methods=['GET', 'POST'])
def github():
    """Render the GitHub page and handle form submission."""
    form = GitHubForm()

    if form.validate_on_submit():
        try:
            # Authenticate with GitHub
            github_auth = GitHubAuth(token=form.token.data)

            # Get the repositories
            repositories = github_auth.list_repositories()

            # Store the token in the session
            session['github_token'] = form.token.data

            # Store the repositories in the session
            session['repositories'] = [repo.full_name for repo in repositories]

            # Redirect to the repositories page
            return redirect(url_for('repositories'))
        except Exception as e:
            flash(f'Error authenticating with GitHub: {e}', 'danger')

    return render_template('github.html', form=form)


@app.route('/repositories')
def repositories():
    """Render the repositories page."""
    # Get the repositories from the session
    repositories = session.get('repositories', None)

    if not repositories:
        flash('No repositories found. Please login to GitHub first.', 'warning')
        return redirect(url_for('github'))

    return render_template('repositories.html', repositories=repositories)


@app.route('/repository/<path:repo_name>')
def repository(repo_name):
    """Render the repository page."""
    # Get the token from the session
    token = session.get('github_token', None)

    if not token:
        flash('No GitHub token found. Please login to GitHub first.', 'warning')
        return redirect(url_for('github'))

    try:
        # Authenticate with GitHub
        github_auth = GitHubAuth(token=token)

        # Get the repository
        repo = github_auth.get_repository(repo_name)

        # Get the repository details
        repo_details = {
            'name': repo.name,
            'full_name': repo.full_name,
            'description': repo.description,
            'url': repo.html_url,
            'stars': repo.stargazers_count,
            'forks': repo.forks_count,
            'open_issues': repo.open_issues_count,
            'default_branch': repo.default_branch
        }

        return render_template('repository.html', repo=repo_details)
    except Exception as e:
        flash(f'Error retrieving repository: {e}', 'danger')
        return redirect(url_for('repositories'))


@app.route('/create_pr', methods=['POST'])
def create_pr():
    """Create a pull request with fixes."""
    # Get the results from the session
    formatted_results = session.get('scan_results', None)

    if not formatted_results:
        flash('No scan results found. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))

    # Get the GitHub token and repository from the request
    github_token = request.form.get('github_token')
    repo_name = request.form.get('repo_name')

    if not github_token or not repo_name:
        flash('GitHub token and repository name are required.', 'danger')
        return redirect(url_for('results'))

    try:
        # Extract vulnerabilities from the formatted results
        vulnerabilities = []

        # Check if there are no vulnerabilities found in the scan results
        if "No vulnerabilities found" in formatted_results or "No vulnerabilities with fixes found" in formatted_results:
            session['pr_creation_info'] = {
                'repo': repo_name,
                'error': 'No vulnerabilities with fixes found in the scan results.'
            }
            flash('No vulnerabilities with fixes found in the scan results. Cannot create a pull request.', 'warning')
            return redirect(url_for('results'))

        # Log the formatted results for debugging
        logging.info(f"Scan results length: {len(formatted_results)}")
        logging.info(f"Scan results preview: {formatted_results[:500]}...")

        # Save the formatted results to a file for debugging
        with open('scan_results_debug.txt', 'w') as f:
            f.write(formatted_results)

        # Try different regex patterns to extract vulnerability information
        # Pattern 1: Standard format with markdown headers
        pattern1 = r'### \d+\. ([^\n]+)\n.*?\*\*File\*\*: `([^`]+)`\n.*?\*\*Line\*\*: (\d+).*?\*\*Vulnerable Code:\*\*\n```\n([\s\S]*?)\n```\n\n\*\*Suggested Fix:\*\*\n```\n([\s\S]*?)\n```'
        vuln_sections = re.findall(pattern1, formatted_results)

        # If no vulnerabilities found with pattern 1, try pattern 2 (simpler format)
        if not vuln_sections:
            logging.info("Pattern 1 did not match any vulnerabilities, trying pattern 2")
            pattern2 = r'\*\*Vulnerability\*\*: ([^\n]+)\n.*?\*\*File\*\*: `([^`]+)`\n.*?\*\*Line\*\*: (\d+).*?\*\*Code:\*\*\n```\n([\s\S]*?)\n```\n\n\*\*Fix:\*\*\n```\n([\s\S]*?)\n```'
            vuln_sections = re.findall(pattern2, formatted_results)

        # If still no vulnerabilities found, try pattern 3 (even simpler format)
        if not vuln_sections:
            logging.info("Pattern 2 did not match any vulnerabilities, trying pattern 3")
            pattern3 = r'([^\n]+) in `([^`]+)` at line (\d+)\n```\n([\s\S]*?)\n```\n\n```\n([\s\S]*?)\n```'
            vuln_sections = re.findall(pattern3, formatted_results)

        # If still no vulnerabilities found, try pattern 4 (fix format)
        if not vuln_sections:
            logging.info("Pattern 3 did not match any vulnerabilities, trying pattern 4")
            pattern4 = r'Fix for ([^\n]+) in ([^:\n]+):(\d+)\nOriginal Code\n(?:\d+\s+)?([\s\S]*?)\nSuggested Fix\n(?:\d+\s+)?([\s\S]*?)(?:\n\nFix for|$)'
            vuln_sections = re.findall(pattern4, formatted_results)

            # Log the matches for debugging
            logging.info(f"Pattern 4 found {len(vuln_sections)} matches")
            for i, match in enumerate(vuln_sections):
                logging.info(f"Match {i+1}: {match[0]} in {match[1]}:{match[2]}")

        # If still no vulnerabilities found, try pattern 5 (another fix format)
        if not vuln_sections:
            logging.info("Pattern 4 did not match any vulnerabilities, trying pattern 5")
            pattern5 = r'Fix for ([^\n]+)\nOriginal Code\n(?:\d+\s+)?([\s\S]*?)\nSuggested Fix\n(?:\d+\s+)?([\s\S]*?)(?:\n\nFix for|$)'
            matches = re.findall(pattern5, formatted_results)

            # Log the matches for debugging
            logging.info(f"Pattern 5 found {len(matches)} matches")
            for i, match in enumerate(matches):
                logging.info(f"Match {i+1}: {match[0]}")

            # Convert matches to the expected format (title, file, line, code, fix)
            for match in matches:
                title = match[0]
                # Try to extract file and line from title
                file_line_match = re.search(r'in ([^:\n]+):(\d+)', title)
                if file_line_match:
                    file_path = file_line_match.group(1)
                    line_num = file_line_match.group(2)
                    vuln_sections.append((title, file_path, line_num, match[1], match[2]))
                    logging.info(f"Extracted file: {file_path}, line: {line_num} from title: {title}")
                else:
                    # Use default values if file and line can't be extracted
                    vuln_sections.append((title, "unknown.py", "1", match[1], match[2]))
                    logging.info(f"Could not extract file and line from title: {title}")

        # If still no vulnerabilities found, try pattern 6 (direct extraction from the vulnerability section)
        if not vuln_sections:
            logging.info("Pattern 5 did not match any vulnerabilities, trying pattern 6")
            # Look for the vulnerability section with code and fix
            pattern6 = r'\*\*Vulnerable Code:\*\*\n\n```\n([\s\S]*?)\n```\n\n\*\*Suggested Fix:\*\*\n\n```\n([\s\S]*?)\n```\n\nFix for ([^\n]+) in ([^:\n]+):(\d+)'
            matches = re.findall(pattern6, formatted_results)

            # Log the matches for debugging
            logging.info(f"Pattern 6 found {len(matches)} matches")
            for i, match in enumerate(matches):
                logging.info(f"Match {i+1}: {match[2]} in {match[3]}:{match[4]}")

            # Convert matches to the expected format (title, file, line, code, fix)
            for match in matches:
                vuln_code = match[0]
                fix_code = match[1]
                title = match[2]
                file_path = match[3]
                line_num = match[4]
                vuln_sections.append((title, file_path, line_num, vuln_code, fix_code))
                logging.info(f"Extracted vulnerability: {title} in {file_path}:{line_num}")

        logging.info(f"Found {len(vuln_sections)} vulnerability sections")

        for title, file, line, vuln_code, fix_code in vuln_sections:
            # Skip if the original code and fix code are the same (no actual fix)
            if vuln_code.strip() == fix_code.strip():
                logging.warning(f"Skipping vulnerability '{title}' in {file}:{line} because the fix is identical to the original code")
                continue

            vulnerabilities.append({
                'title': title,
                'file': file,
                'line': int(line),
                'vulnerable_code': vuln_code,
                'fix_code': fix_code
            })

        if not vulnerabilities:
            # Try to extract raw vulnerability information from the scan results
            logging.info("No structured vulnerabilities found, trying to extract raw information")

            # Look for any mentions of vulnerabilities in the scan results
            vuln_mentions = re.findall(r'([^\n]+vulnerability[^\n]+)', formatted_results, re.IGNORECASE)
            file_mentions = re.findall(r'`([^`]+\.(py|js|java|php|rb|go))`', formatted_results)

            # Create a detailed error message
            error_message = 'Could not extract vulnerability information from the scan results.'
            if vuln_mentions:
                error_message += f" Found {len(vuln_mentions)} mentions of vulnerabilities but couldn't parse them properly."
            if file_mentions:
                error_message += f" Found references to {len(file_mentions)} files."

            # Store detailed information in the session
            session['pr_creation_info'] = {
                'repo': repo_name,
                'error': error_message,
                'scan_results_preview': formatted_results[:1000] if formatted_results else 'No results',
                'vuln_mentions': vuln_mentions[:5] if vuln_mentions else [],
                'file_mentions': file_mentions[:5] if file_mentions else []
            }

            flash(error_message, 'warning')
            return redirect(url_for('results'))

        # Create a temporary directory for the repository
        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone the repository
            github_auth = GitHubAuth(token=github_token)
            github_auth.clone_repository(repo_name, temp_dir)

            # Create a PR creator
            pr_creator = PRCreator(github_token, repo_name, temp_dir)

            # Create a branch name based on the current date and time
            from datetime import datetime
            branch_name = f"security-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

            # Create a new branch
            if not pr_creator.create_branch(branch_name):
                flash('Failed to create branch.', 'danger')
                return redirect(url_for('results'))

            # Apply fixes
            for vuln in vulnerabilities:
                file_path = os.path.join(temp_dir, vuln['file'])

                # Make sure the file exists
                if not os.path.exists(file_path):
                    continue

                # Read the file content
                with open(file_path, 'r') as f:
                    content = f.read()

                # Replace the vulnerable code with the fix
                new_content = content.replace(vuln['vulnerable_code'], vuln['fix_code'])

                # Write the new content back to the file
                with open(file_path, 'w') as f:
                    f.write(new_content)

            # Commit changes
            commit_message = "Fix security vulnerabilities"
            if not pr_creator.commit_changes(commit_message):
                flash('Failed to commit changes.', 'danger')
                return redirect(url_for('results'))

            # Push changes
            try:
                push_result = pr_creator.push_changes(branch_name)
                if not push_result:
                    # Store information about the changes in the session for manual PR creation
                    session['pr_creation_info'] = {
                        'repo': repo_name,
                        'branch': branch_name,
                        'vulnerabilities': len(vulnerabilities),
                        'files_changed': [vuln['file'] for vuln in vulnerabilities],
                        'error': 'Failed to push changes to GitHub.'
                    }

                    flash('Failed to push changes to GitHub. This could be due to authentication issues or repository permissions. '
                          'Please check your GitHub token and ensure you have write access to the repository.', 'danger')
                    return redirect(url_for('results'))
            except Exception as e:
                # Store information about the changes in the session for manual PR creation
                session['pr_creation_info'] = {
                    'repo': repo_name,
                    'branch': branch_name,
                    'vulnerabilities': len(vulnerabilities),
                    'files_changed': [vuln['file'] for vuln in vulnerabilities],
                    'error': str(e)
                }

                flash(f'Error pushing changes to GitHub: {str(e)}. Please check your GitHub token and repository permissions.', 'danger')
                return redirect(url_for('results'))

            # Create PR
            pr_title = "Fix security vulnerabilities"
            pr_body = f"This PR fixes {len(vulnerabilities)} security vulnerabilities.\n\n"
            pr_body += "## Vulnerabilities Fixed\n\n"

            for i, vuln in enumerate(vulnerabilities, 1):
                pr_body += f"### {i}. {vuln['title']}\n"
                pr_body += f"- **File**: `{vuln['file']}`\n"
                pr_body += f"- **Line**: {vuln['line']}\n\n"

            pr = pr_creator.create_pull_request(branch_name, pr_title, pr_body)

            if not pr:
                flash('Failed to create PR.', 'danger')
                return redirect(url_for('results'))

            # Store the PR information in the session
            session['pr_info'] = {
                'number': pr['number'],
                'url': pr['url'],
                'repo': repo_name,
                'branch': branch_name
            }

            flash(f'Pull request created successfully: {pr["url"]}', 'success')
            return redirect(url_for('results'))

    except Exception as e:
        flash(f'Error creating PR: {str(e)}', 'danger')
        return redirect(url_for('results'))


@app.route('/download_fixes', methods=['POST'])
def download_fixes():
    """Download fixed files and create a pull request manually."""
    # Get the repository URL, GitHub token, and branch name from the form
    repo_url = request.form.get('repo_url')
    github_token = request.form.get('github_token')
    branch_name = request.form.get('branch_name')

    if not repo_url or not github_token:
        flash('Repository URL and GitHub token are required.', 'danger')
        return redirect(url_for('results'))

    # Get the results from the session
    formatted_results = session.get('scan_results', None)

    if not formatted_results:
        flash('No scan results found. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))

    try:
        # Extract vulnerabilities from the formatted results using the same logic as in create_pr
        vulnerabilities = []

        # Try different regex patterns to extract vulnerability information
        # Pattern 1: Standard format with markdown headers
        pattern1 = r'### \d+\. ([^\n]+)\n.*?\*\*File\*\*: `([^`]+)`\n.*?\*\*Line\*\*: (\d+).*?\*\*Vulnerable Code:\*\*\n```\n([\s\S]*?)\n```\n\n\*\*Suggested Fix:\*\*\n```\n([\s\S]*?)\n```'
        vuln_sections = re.findall(pattern1, formatted_results)

        # If no vulnerabilities found with pattern 1, try pattern 2 (simpler format)
        if not vuln_sections:
            pattern2 = r'\*\*Vulnerability\*\*: ([^\n]+)\n.*?\*\*File\*\*: `([^`]+)`\n.*?\*\*Line\*\*: (\d+).*?\*\*Code:\*\*\n```\n([\s\S]*?)\n```\n\n\*\*Fix:\*\*\n```\n([\s\S]*?)\n```'
            vuln_sections = re.findall(pattern2, formatted_results)

        # If still no vulnerabilities found, try pattern 3 (even simpler format)
        if not vuln_sections:
            pattern3 = r'([^\n]+) in `([^`]+)` at line (\d+)\n```\n([\s\S]*?)\n```\n\n```\n([\s\S]*?)\n```'
            vuln_sections = re.findall(pattern3, formatted_results)

        # If still no vulnerabilities found, try pattern 4 (fix format)
        if not vuln_sections:
            pattern4 = r'Fix for ([^\n]+) in ([^:\n]+):(\d+)\nOriginal Code\n(?:\d+\s+)?([\s\S]*?)\nSuggested Fix\n(?:\d+\s+)?([\s\S]*?)(?:\n\nFix for|$)'
            vuln_sections = re.findall(pattern4, formatted_results)

        # If still no vulnerabilities found, try pattern 5 (another fix format)
        if not vuln_sections:
            pattern5 = r'Fix for ([^\n]+)\nOriginal Code\n(?:\d+\s+)?([\s\S]*?)\nSuggested Fix\n(?:\d+\s+)?([\s\S]*?)(?:\n\nFix for|$)'
            matches = re.findall(pattern5, formatted_results)

            # Convert matches to the expected format (title, file, line, code, fix)
            for match in matches:
                title = match[0]
                # Try to extract file and line from title
                file_line_match = re.search(r'in ([^:\n]+):(\d+)', title)
                if file_line_match:
                    file_path = file_line_match.group(1)
                    line_num = file_line_match.group(2)
                    vuln_sections.append((title, file_path, line_num, match[1], match[2]))
                else:
                    # Use default values if file and line can't be extracted
                    vuln_sections.append((title, "code.js", "1", match[1], match[2]))

        for title, file, line, vuln_code, fix_code in vuln_sections:
            # Skip if the original code and fix code are the same (no actual fix)
            if vuln_code.strip() == fix_code.strip():
                continue

            vulnerabilities.append({
                'title': title,
                'file': file,
                'line': int(line),
                'vulnerable_code': vuln_code,
                'fix_code': fix_code
            })

        if not vulnerabilities:
            flash('No vulnerabilities with fixes found in the scan results.', 'warning')
            return redirect(url_for('results'))

        # Create a temporary directory for the fixed files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a directory structure for the fixed files
            for vuln in vulnerabilities:
                file_path = os.path.join(temp_dir, vuln['file'])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # Create the fixed file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(vuln['fix_code'])

            # Create a README.md file with instructions
            readme_path = os.path.join(temp_dir, 'README.md')
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(f"# Security Fixes\n\n")
                f.write(f"This directory contains fixed files for security vulnerabilities found in {repo_url}.\n\n")
                f.write(f"## Vulnerabilities Fixed\n\n")

                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"### {i}. {vuln['title']}\n")
                    f.write(f"- **File**: `{vuln['file']}`\n")
                    f.write(f"- **Line**: {vuln['line']}\n\n")

                f.write(f"## Instructions\n\n")
                f.write(f"1. Create a new branch in your repository\n")
                f.write(f"2. Copy these fixed files to your repository\n")
                f.write(f"3. Commit and push the changes\n")
                f.write(f"4. Create a pull request\n\n")

                f.write(f"Alternatively, you can use the `create_pr.py` script to create a pull request automatically:\n\n")
                f.write(f"```\npython create_pr.py {repo_url} YOUR_GITHUB_TOKEN\n```\n")

            # Create a zip file with the fixed files
            import shutil
            zip_path = os.path.join(os.path.dirname(temp_dir), 'security_fixes.zip')
            shutil.make_archive(zip_path[:-4], 'zip', temp_dir)

            # Return the zip file as a download
            from flask import send_file
            return send_file(zip_path, as_attachment=True, download_name='security_fixes.zip')

    except Exception as e:
        flash(f'Error creating fixed files: {str(e)}', 'danger')
        return redirect(url_for('results'))


@app.route('/browse_directory', methods=['GET'])
def browse_directory():
    """Browse directories for the scan form."""
    # Get the current directory from the query parameters
    current_dir = request.args.get('dir', os.path.expanduser('~'))

    try:
        # Convert to Path object for easier manipulation
        path = Path(current_dir)

        # Make sure the path exists and is a directory
        if not path.exists() or not path.is_dir():
            return jsonify({
                'success': False,
                'error': f'Directory {current_dir} does not exist or is not a directory',
                'current_dir': str(path.parent),
                'directories': []
            })

        # Get all subdirectories
        directories = []
        for item in path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                directories.append({
                    'name': item.name,
                    'path': str(item),
                    'is_dir': True
                })

        # Sort directories by name
        directories.sort(key=lambda x: x['name'])

        # Add parent directory if not at root
        if path.parent != path:
            directories.insert(0, {
                'name': '..',
                'path': str(path.parent),
                'is_dir': True
            })

        return jsonify({
            'success': True,
            'current_dir': str(path),
            'directories': directories
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'current_dir': current_dir,
            'directories': []
        })


@app.route('/merge_pr', methods=['POST'])
def merge_pr():
    """Merge a pull request."""
    # Get the PR information from the session
    pr_info = session.get('pr_info', None)

    if not pr_info:
        flash('No pull request information found.', 'warning')
        return redirect(url_for('results'))

    # Get the GitHub token from the request
    github_token = request.form.get('github_token')

    if not github_token:
        flash('GitHub token is required.', 'danger')
        return redirect(url_for('results'))

    try:
        # Authenticate with GitHub
        github = GitHubAuth(token=github_token).github

        # Get the repository
        repo = github.get_repo(pr_info['repo'])

        # Get the pull request
        pr = repo.get_pull(pr_info['number'])

        # Merge the pull request
        merge_result = pr.merge()

        if merge_result.merged:
            flash('Pull request merged successfully.', 'success')

            # Update the PR information in the session
            pr_info['merged'] = True
            session['pr_info'] = pr_info
        else:
            flash(f'Failed to merge PR: {merge_result.message}', 'danger')

        return redirect(url_for('results'))

    except Exception as e:
        flash(f'Error merging PR: {str(e)}', 'danger')
        return redirect(url_for('results'))


if __name__ == '__main__':
    app.run(debug=True)
