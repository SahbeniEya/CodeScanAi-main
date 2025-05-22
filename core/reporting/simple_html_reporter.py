"""
This module provides a simple HTML report generation for security scan results.
"""

import json
import logging
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

def generate_html_report(input_file, output_file):
    """
    Generate a simple HTML report from scan results.
    
    Args:
        input_file (str): Path to the input JSON file.
        output_file (str): Path to the output HTML file.
    """
    try:
        # Read the scan results
        with open(input_file, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        # Extract vulnerabilities
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
        low_count = len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
        total_count = len(vulnerabilities)
        
        # Generate vulnerability HTML
        vulnerabilities_html = ""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            severity_class = severity.lower()
            
            # Get the title (first sentence of description)
            description = vuln.get('description', '')
            title = description.split('.')[0] if description else vuln.get('id', '')
            
            # Format the vulnerability HTML
            vuln_html = f"""
            <div class="card mb-3 border-{severity_class}">
                <div class="card-header bg-{severity_class} text-white">
                    <h5 class="card-title mb-0">{vuln.get('id', '')}: {title}</h5>
                </div>
                <div class="card-body">
                    <p><strong>File:</strong> {vuln.get('file_path', '')}</p>
                    <p><strong>Line:</strong> {vuln.get('line_number', 0)}</p>
                    <p><strong>Description:</strong> {description}</p>
                    <h6>Code Snippet:</h6>
                    <pre><code>{vuln.get('code', '').replace('<', '&lt;').replace('>', '&gt;')}</code></pre>
                    <h6>Fix Suggestion:</h6>
                    <pre><code>{vuln.get('fix_suggestion', '').replace('<', '&lt;').replace('>', '&gt;')}</code></pre>
                </div>
            </div>
            """
            vulnerabilities_html += vuln_html
        
        # Generate the HTML report
        html_report = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                .border-high {{ border-left: 5px solid #dc3545; }}
                .border-medium {{ border-left: 5px solid #ffc107; }}
                .border-low {{ border-left: 5px solid #0dcaf0; }}
                .bg-high {{ background-color: #dc3545; }}
                .bg-medium {{ background-color: #ffc107; color: #000 !important; }}
                .bg-low {{ background-color: #0dcaf0; color: #000 !important; }}
                pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="container py-5">
                <h1 class="mb-4">Security Scan Report</h1>
                <p class="lead">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card text-white bg-danger">
                            <div class="card-body text-center">
                                <h5 class="card-title">High Severity</h5>
                                <h2 class="display-4">{high_count}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-dark bg-warning">
                            <div class="card-body text-center">
                                <h5 class="card-title">Medium Severity</h5>
                                <h2 class="display-4">{medium_count}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-dark bg-info">
                            <div class="card-body text-center">
                                <h5 class="card-title">Low Severity</h5>
                                <h2 class="display-4">{low_count}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-dark">
                            <div class="card-body text-center">
                                <h5 class="card-title">Total</h5>
                                <h2 class="display-4">{total_count}</h2>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h2 class="mb-4">Vulnerabilities</h2>
                {vulnerabilities_html}
                
                <footer class="mt-5 text-center text-muted">
                    <p>Generated by CodeScanAI Security Scanner</p>
                </footer>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """
        
        # Write the HTML report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        logging.info(f"HTML report generated: {output_file}")
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")


def main():
    """
    Main function to generate an HTML report from the command line.
    """
    parser = argparse.ArgumentParser(description='Generate an HTML report from security scan results.')
    parser.add_argument('--input-file', '-i', required=True, help='Path to the input JSON file')
    parser.add_argument('--output-file', '-o', required=True, help='Path to the output HTML file')
    
    args = parser.parse_args()
    
    generate_html_report(args.input_file, args.output_file)


if __name__ == '__main__':
    main()
