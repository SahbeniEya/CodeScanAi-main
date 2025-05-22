"""
This module handles GitHub authentication and repository selection.
"""

import os
import logging
from github import Github

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class GitHubAuth:
    """
    Handles GitHub authentication and repository operations.
    """

    def __init__(self, token=None):
        """
        Initialize GitHub authentication with a token.

        Args:
            token (str, optional): GitHub personal access token. If not provided,
                                  will try to get from environment variable.
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError(
                "GitHub token is required. Set the GITHUB_TOKEN environment variable or provide it directly."
            )
        self.github = Github(self.token)
        self.user = self.github.get_user()
        logging.info(f"Authenticated as GitHub user: {self.user.login}")

    def list_repositories(self, include_forks=False):
        """
        List repositories accessible by the authenticated user.

        Args:
            include_forks (bool): Whether to include forked repositories.

        Returns:
            list: List of repository objects.
        """
        repos = []
        for repo in self.user.get_repos():
            if include_forks or not repo.fork:
                repos.append(repo)

        logging.info(f"Found {len(repos)} repositories")
        return repos

    def get_repository(self, repo_name):
        """
        Get a specific repository by name.

        Args:
            repo_name (str): Repository name in format "owner/repo".

        Returns:
            Repository: GitHub repository object.
        """
        try:
            repo = self.github.get_repo(repo_name)
            logging.info(f"Retrieved repository: {repo.full_name}")
            return repo
        except Exception as e:
            logging.error(f"Error retrieving repository {repo_name}: {e}")
            raise ValueError(f"Repository {repo_name} not found or not accessible.")

    def clone_repository(self, repo_name, local_path):
        """
        Clone a repository to a local path.

        Args:
            repo_name (str): Repository name in format "owner/repo".
            local_path (str): Local path to clone the repository to.

        Returns:
            str: Path to the cloned repository.
        """
        import subprocess
        import os

        repo = self.get_repository(repo_name)

        # Use HTTPS URL with token for authentication
        clone_url = f"https://x-access-token:{self.token}@github.com/{repo_name}.git"

        logging.info(f"Cloning repository {repo_name} to {local_path}...")

        try:
            # Clone the repository
            subprocess.check_call(
                ["git", "clone", clone_url, local_path],
                stderr=subprocess.STDOUT
            )

            # Configure Git in the cloned repository
            os.chdir(local_path)

            # Set Git identity if not already set
            try:
                # Check if user.name and user.email are set
                subprocess.check_call(["git", "config", "user.name"])
                subprocess.check_call(["git", "config", "user.email"])
            except subprocess.CalledProcessError:
                # Set default values if not set
                subprocess.check_call(["git", "config", "user.name", "CodeScanAI"])
                subprocess.check_call(["git", "config", "user.email", "codescanai@example.com"])

            # Configure Git to use the token for authentication
            subprocess.check_call(["git", "config", "http.https://github.com/.extraheader", f"AUTHORIZATION: basic {self.token}"])

            # Change back to the original directory
            os.chdir(os.path.dirname(os.path.dirname(local_path)))

            logging.info(f"Cloned repository {repo_name} to {local_path}")
            return local_path
        except subprocess.CalledProcessError as e:
            logging.error(f"Error cloning repository: {e}")
            raise ValueError(f"Failed to clone repository {repo_name}.")
