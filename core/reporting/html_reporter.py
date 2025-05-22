"""
This module provides HTML report generation for security scan results.
"""

import os
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# HTML template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; margin-bottom: 20px; border-radius: 5px; }
        h1, h2, h3, h4 { margin-top: 0; }
        .summary { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .summary-card { background-color: white; border-radius: 5px; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; margin: 0 10px; text-align: center; }
        .high { border-top: 5px solid #e74c3c; }
        .medium { border-top: 5px solid #f39c12; }
        .low { border-top: 5px solid #3498db; }
        .total { border-top: 5px solid #2c3e50; }
        .count { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .high .count { color: #e74c3c; }
        .medium .count { color: #f39c12; }
        .low .count { color: #3498db; }
        .total .count { color: #2c3e50; }
        .vulnerability { background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vulnerability.high { border-left: 5px solid #e74c3c; }
        .vulnerability.medium { border-left: 5px solid #f39c12; }
        .vulnerability.low { border-left: 5px solid #3498db; }
        .vulnerability-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .vulnerability-title { margin: 0; font-size: 18px; }
        .severity { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .severity.high { background-color: #e74c3c; }
        .severity.medium { background-color: #f39c12; }
        .severity.low { background-color: #3498db; }
        .details { margin-bottom: 15px; }
        .details p { margin: 5px 0; }
        .file-path { font-family: monospace; background-color: #f8f9fa; padding: 5px; border-radius: 3px; }
        .code-snippet { background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; white-space: pre; margin-bottom: 15px; }
        .fix-suggestion { background-color: #e8f4f8; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre; margin-bottom: 15px; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background-color: #ddd; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
        .tab.active { background-color: white; border-bottom: none; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        footer { text-align: center; margin-top: 30px; padding: 20px; color: #7f8c8d; font-size: 14px; }
        .chart-container { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .chart { background-color: white; border-radius: 5px; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; margin: 0 10px; height: 300px; }
        @media (max-width: 768px) { .summary, .chart-container { flex-direction: column; } .summary-card, .chart { margin: 10px 0; } }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <p>Generated on {date}</p>
        </header>

        <div class="summary">
            <div class="summary-card high">
                <h3>High Severity</h3>
                <div class="count">{high_count}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Severity</h3>
                <div class="count">{medium_count}</div>
            </div>
            <div class="summary-card low">
                <h3>Low Severity</h3>
                <div class="count">{low_count}</div>
            </div>
            <div class="summary-card total">
                <h3>Total</h3>
                <div class="count">{total_count}</div>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart">
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="openTab(event, 'all')">All</div>
            <div class="tab" onclick="openTab(event, 'high')">High</div>
            <div class="tab" onclick="openTab(event, 'medium')">Medium</div>
            <div class="tab" onclick="openTab(event, 'low')">Low</div>
        </div>

        <div id="all" class="tab-content active">
            {all_vulnerabilities}
        </div>

        <div id="high" class="tab-content">
            {high_vulnerabilities}
        </div>

        <div id="medium" class="tab-content">
            {medium_vulnerabilities}
        </div>

        <div id="low" class="tab-content">
            {low_vulnerabilities}
        </div>

        <footer>
            <p>Generated by CodeScanAI Security Scanner</p>
        </footer>
    </div>

    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }
            tablinks = document.getElementsByClassName("tab");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }

        // Severity chart
        var severityCtx = document.getElementById('severityChart').getContext('2d');
        var severityChart = new Chart(severityCtx, {
            type: 'pie',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: [{high_count}, {medium_count}, {low_count}],
                    backgroundColor: ['#e74c3c', '#f39c12', '#3498db']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Vulnerabilities by Severity'
                    }
                }
            }
        });

        // Type chart
        var typeCtx = document.getElementById('typeChart').getContext('2d');
        var typeChart = new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: {type_labels},
                datasets: [{
                    label: 'Count',
                    data: {type_counts},
                    backgroundColor: '#2c3e50'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Vulnerabilities by Type'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>"""

# Vulnerability template
VULNERABILITY_TEMPLATE = """
<div class="vulnerability {severity_class}">
    <div class="vulnerability-header">
        <h3 class="vulnerability-title">{id}: {title}</h3>
        <span class="severity {severity_class}">{severity}</span>
    </div>
    <div class="details">
        <p><strong>File:</strong> <span class="file-path">{file_path}</span></p>
        <p><strong>Line:</strong> {line_number}</p>
        <p><strong>Description:</strong> {description}</p>
    </div>
    <h4>Code Snippet:</h4>
    <div class="code-snippet">{code}</div>
    <h4>Fix Suggestion:</h4>
    <div class="fix-suggestion">{fix_suggestion}</div>
</div>
"""

class HTMLReporter:
    """
    HTML reporter for security scan results.
    """

    def __init__(self, input_file: str, output_file: str):
        """
        Initialize the HTML reporter.

        Args:
            input_file (str): Path to the input JSON file.
            output_file (str): Path to the output HTML file.
        """
        self.input_file = input_file
        self.output_file = output_file

    def generate_report(self) -> None:
        """
        Generate an HTML report from the scan results.
        """
        try:
            # Read the scan results
            with open(self.input_file, 'r', encoding='utf-8') as f:
                scan_results = json.load(f)

            # Extract vulnerabilities
            vulnerabilities = scan_results.get('vulnerabilities', [])

            # Count vulnerabilities by severity
            high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
            medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
            low_count = len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
            total_count = len(vulnerabilities)

            # Count vulnerabilities by type
            vulnerability_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('id', '').split('-')[0]
                if vuln_type not in vulnerability_types:
                    vulnerability_types[vuln_type] = 0
                vulnerability_types[vuln_type] += 1

            # Sort vulnerability types by count
            sorted_types = sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True)
            type_labels = [f'"{t[0]}"' for t in sorted_types]
            type_counts = [t[1] for t in sorted_types]

            # Generate vulnerability HTML
            all_vulnerabilities_html = ""
            high_vulnerabilities_html = ""
            medium_vulnerabilities_html = ""
            low_vulnerabilities_html = ""

            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'LOW')
                severity_class = severity.lower()

                # Get the title (first sentence of description)
                description = vuln.get('description', '')
                title = description.split('.')[0] if description else vuln.get('id', '')

                # Format the vulnerability HTML
                vuln_html = VULNERABILITY_TEMPLATE.format(
                    id=vuln.get('id', ''),
                    title=title,
                    severity=severity,
                    severity_class=severity_class,
                    file_path=vuln.get('file_path', ''),
                    line_number=vuln.get('line_number', 0),
                    description=description,
                    code=vuln.get('code', '').replace('<', '&lt;').replace('>', '&gt;'),
                    fix_suggestion=vuln.get('fix_suggestion', '').replace('<', '&lt;').replace('>', '&gt;')
                )

                all_vulnerabilities_html += vuln_html

                if severity == 'HIGH':
                    high_vulnerabilities_html += vuln_html
                elif severity == 'MEDIUM':
                    medium_vulnerabilities_html += vuln_html
                else:
                    low_vulnerabilities_html += vuln_html

            # Generate the HTML report
            html_report = HTML_TEMPLATE.format(
                date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                total_count=total_count,
                all_vulnerabilities=all_vulnerabilities_html,
                high_vulnerabilities=high_vulnerabilities_html,
                medium_vulnerabilities=medium_vulnerabilities_html,
                low_vulnerabilities=low_vulnerabilities_html,
                type_labels=f"[{', '.join(type_labels)}]",
                type_counts=f"[{', '.join(map(str, type_counts))}]"
            )

            # Write the HTML report
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(html_report)

            logging.info(f"HTML report generated: {self.output_file}")
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

    reporter = HTMLReporter(args.input_file, args.output_file)
    reporter.generate_report()


if __name__ == '__main__':
    main()
