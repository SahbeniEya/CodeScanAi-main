"""
This module provides a simple dashboard for displaying security metrics.
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

from core.scanners.sast_scanner import Vulnerability

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class SecurityMetrics:
    """
    Tracks and stores security metrics.
    """
    
    def __init__(self, metrics_file: Optional[str] = None):
        """
        Initialize the security metrics.
        
        Args:
            metrics_file (Optional[str]): Path to the metrics file. If not provided,
                                         a default path will be used.
        """
        self.metrics_file = metrics_file or os.path.join(os.path.expanduser("~"), ".codescanai", "metrics.json")
        self.metrics = self._load_metrics()
    
    def _load_metrics(self) -> Dict[str, Any]:
        """
        Load metrics from the metrics file.
        
        Returns:
            Dict[str, Any]: Loaded metrics.
        """
        if not os.path.exists(self.metrics_file):
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
            
            # Return default metrics
            return {
                "scans": [],
                "vulnerabilities": {
                    "total": 0,
                    "fixed": 0,
                    "by_severity": {
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0
                    }
                },
                "fixes": {
                    "total": 0,
                    "successful": 0,
                    "failed": 0
                },
                "prs": {
                    "total": 0,
                    "merged": 0,
                    "closed": 0,
                    "open": 0
                }
            }
        
        try:
            with open(self.metrics_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Error loading metrics from {self.metrics_file}")
            return {
                "scans": [],
                "vulnerabilities": {
                    "total": 0,
                    "fixed": 0,
                    "by_severity": {
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0
                    }
                },
                "fixes": {
                    "total": 0,
                    "successful": 0,
                    "failed": 0
                },
                "prs": {
                    "total": 0,
                    "merged": 0,
                    "closed": 0,
                    "open": 0
                }
            }
    
    def _save_metrics(self):
        """
        Save metrics to the metrics file.
        """
        try:
            with open(self.metrics_file, 'w', encoding='utf-8') as f:
                json.dump(self.metrics, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving metrics to {self.metrics_file}: {e}")
    
    def record_scan(self, vulnerabilities: List[Vulnerability], repo_name: Optional[str] = None):
        """
        Record a scan in the metrics.
        
        Args:
            vulnerabilities (List[Vulnerability]): Vulnerabilities found in the scan.
            repo_name (Optional[str]): Name of the repository scanned.
        """
        # Count vulnerabilities by severity
        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["LOW"] += 1  # Default to LOW if unknown
        
        # Create a scan record
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "repo_name": repo_name,
            "vulnerabilities": {
                "total": len(vulnerabilities),
                "by_severity": severity_counts
            }
        }
        
        # Add the scan record to the metrics
        self.metrics["scans"].append(scan_record)
        
        # Update vulnerability counts
        self.metrics["vulnerabilities"]["total"] += len(vulnerabilities)
        for severity, count in severity_counts.items():
            self.metrics["vulnerabilities"]["by_severity"][severity] += count
        
        # Save the metrics
        self._save_metrics()
    
    def record_fixes(self, successful_fixes: int, failed_fixes: int):
        """
        Record fixes in the metrics.
        
        Args:
            successful_fixes (int): Number of successful fixes.
            failed_fixes (int): Number of failed fixes.
        """
        # Update fix counts
        self.metrics["fixes"]["total"] += successful_fixes + failed_fixes
        self.metrics["fixes"]["successful"] += successful_fixes
        self.metrics["fixes"]["failed"] += failed_fixes
        
        # Update fixed vulnerability count
        self.metrics["vulnerabilities"]["fixed"] += successful_fixes
        
        # Save the metrics
        self._save_metrics()
    
    def record_pr(self, pr_status: str):
        """
        Record a PR in the metrics.
        
        Args:
            pr_status (str): Status of the PR ("open", "merged", or "closed").
        """
        # Update PR counts
        self.metrics["prs"]["total"] += 1
        if pr_status.lower() == "open":
            self.metrics["prs"]["open"] += 1
        elif pr_status.lower() == "merged":
            self.metrics["prs"]["merged"] += 1
        elif pr_status.lower() == "closed":
            self.metrics["prs"]["closed"] += 1
        
        # Save the metrics
        self._save_metrics()
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get the current metrics.
        
        Returns:
            Dict[str, Any]: Current metrics.
        """
        return self.metrics
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the metrics.
        
        Returns:
            Dict[str, Any]: Metrics summary.
        """
        return {
            "vulnerabilities": {
                "total": self.metrics["vulnerabilities"]["total"],
                "fixed": self.metrics["vulnerabilities"]["fixed"],
                "by_severity": self.metrics["vulnerabilities"]["by_severity"]
            },
            "fixes": {
                "total": self.metrics["fixes"]["total"],
                "successful": self.metrics["fixes"]["successful"],
                "success_rate": self.metrics["fixes"]["successful"] / self.metrics["fixes"]["total"] if self.metrics["fixes"]["total"] > 0 else 0
            },
            "prs": {
                "total": self.metrics["prs"]["total"],
                "merged": self.metrics["prs"]["merged"],
                "merge_rate": self.metrics["prs"]["merged"] / self.metrics["prs"]["total"] if self.metrics["prs"]["total"] > 0 else 0
            }
        }


def format_metrics_as_markdown(metrics: Dict[str, Any]) -> str:
    """
    Format metrics as Markdown.
    
    Args:
        metrics (Dict[str, Any]): Metrics to format.
        
    Returns:
        str: Markdown-formatted metrics.
    """
    output = "# Security Metrics Dashboard\n\n"
    
    # Vulnerability metrics
    output += "## Vulnerability Metrics\n\n"
    output += f"- **Total Vulnerabilities**: {metrics['vulnerabilities']['total']}\n"
    output += f"- **Fixed Vulnerabilities**: {metrics['vulnerabilities']['fixed']} ({metrics['vulnerabilities']['fixed'] / metrics['vulnerabilities']['total'] * 100:.1f}% of total)\n"
    output += "\n**Vulnerabilities by Severity:**\n\n"
    output += f"- **High**: {metrics['vulnerabilities']['by_severity']['HIGH']}\n"
    output += f"- **Medium**: {metrics['vulnerabilities']['by_severity']['MEDIUM']}\n"
    output += f"- **Low**: {metrics['vulnerabilities']['by_severity']['LOW']}\n"
    
    # Fix metrics
    output += "\n## Fix Metrics\n\n"
    output += f"- **Total Fixes Attempted**: {metrics['fixes']['total']}\n"
    output += f"- **Successful Fixes**: {metrics['fixes']['successful']}\n"
    output += f"- **Fix Success Rate**: {metrics['fixes']['success_rate'] * 100:.1f}%\n"
    
    # PR metrics
    output += "\n## Pull Request Metrics\n\n"
    output += f"- **Total PRs Created**: {metrics['prs']['total']}\n"
    output += f"- **Merged PRs**: {metrics['prs']['merged']}\n"
    output += f"- **PR Merge Rate**: {metrics['prs']['merge_rate'] * 100:.1f}%\n"
    
    return output
