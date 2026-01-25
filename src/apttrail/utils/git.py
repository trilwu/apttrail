"""
Git operations utilities for APTtrail.

Handles repository management, blame operations, and commit metadata extraction.
"""

import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


class GitOperations:
    """
    Encapsulates git operations for the Maltrail repository.

    Provides methods for cloning, updating, and extracting metadata
    from the git repository.

    Attributes:
        repo_path: Path to the git repository
        timeout: Default timeout for git operations in seconds
    """

    DEFAULT_TIMEOUT: int = 30
    MALTRAIL_URL: str = "https://github.com/stamparm/maltrail.git"
    URL_PATTERN: re.Pattern[str] = re.compile(r"https?://[^\s\)]+")

    def __init__(self, repo_path: Path, timeout: int = DEFAULT_TIMEOUT) -> None:
        """
        Initialize GitOperations.

        Args:
            repo_path: Path to the git repository
            timeout: Timeout for git operations in seconds
        """
        self.repo_path = repo_path
        self.timeout = timeout

    def is_git_repo(self) -> bool:
        """Check if the path is a valid git repository."""
        return (self.repo_path / ".git").exists()

    def clone(self) -> bool:
        """
        Clone the Maltrail repository.

        Returns:
            True if clone succeeded, False otherwise
        """
        try:
            print(f"Cloning Maltrail repository to {self.repo_path}...")
            subprocess.run(
                ["git", "clone", self.MALTRAIL_URL, str(self.repo_path)],
                check=True,
                capture_output=True,
                timeout=120,  # Clone may take longer
            )
            print("Repository cloned successfully")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"Error cloning repository: {e}")
            return False

    def pull(self) -> bool:
        """
        Pull latest changes from the repository.

        Returns:
            True if pull succeeded, False otherwise
        """
        try:
            print(f"Updating Maltrail repository at {self.repo_path}...")
            subprocess.run(
                ["git", "pull"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                timeout=self.timeout,
            )
            print("Repository updated successfully")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"Error updating repository: {e}")
            return False

    def update_or_clone(self) -> bool:
        """
        Update the repository if it exists, otherwise clone it.

        Returns:
            True if operation succeeded, False otherwise
        """
        if self.is_git_repo():
            return self.pull()
        return self.clone()

    def get_file_last_commit_time(self, filepath: Path) -> datetime:
        """
        Get the last commit time for a file.

        Args:
            filepath: Path to the file

        Returns:
            Datetime of last commit, or current time if unavailable
        """
        try:
            relative_path = filepath.relative_to(self.repo_path)
            result = subprocess.run(
                ["git", "log", "-1", "--format=%aI", "--", str(relative_path)],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return datetime.fromisoformat(result.stdout.strip())
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            pass
        return datetime.now()

    def get_file_timestamps_bulk(self, filepath: Path) -> dict[str, dict[str, Any]]:
        """
        Get timestamps and commit info for all lines in a file using git blame.

        Args:
            filepath: Path to the file

        Returns:
            Dictionary mapping line content to {first_seen, commit} info
        """
        timestamps: dict[str, dict[str, Any]] = {}

        try:
            relative_path = filepath.relative_to(self.repo_path)
            result = subprocess.run(
                ["git", "blame", "--line-porcelain", str(relative_path)],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                return timestamps

            current_commit: str | None = None
            current_timestamp: datetime | None = None

            for line in result.stdout.split("\n"):
                # Parse git blame porcelain format
                if line and not line.startswith("\t"):
                    parts = line.split(" ", 1)
                    if len(parts) == 2 and len(parts[0]) == 40:  # SHA1 hash
                        current_commit = parts[0]
                elif line.startswith("author-time "):
                    unix_time = int(line.split()[1])
                    current_timestamp = datetime.fromtimestamp(unix_time)
                elif line.startswith("\t"):
                    # Actual line content
                    content = line[1:].strip()
                    if content and not content.startswith("#") and current_timestamp and current_commit:
                        timestamps[content] = {
                            "first_seen": current_timestamp,
                            "commit": current_commit,
                        }

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as e:
            print(f"Warning: Could not get timestamps for {filepath.name}: {e}")

        return timestamps

    def get_commit_references(self, commit_hashes: set[str]) -> dict[str, list[str]]:
        """
        Extract reference URLs from commit messages.

        Args:
            commit_hashes: Set of commit hashes to look up

        Returns:
            Dictionary mapping commit hash to list of reference URLs
        """
        commit_refs: dict[str, list[str]] = {}

        for commit_hash in commit_hashes:
            try:
                result = subprocess.run(
                    ["git", "log", "-1", "--format=%B", commit_hash],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    urls = self.URL_PATTERN.findall(result.stdout)
                    if urls:
                        commit_refs[commit_hash] = urls

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

        return commit_refs

    def get_current_commit(self) -> str | None:
        """
        Get the current HEAD commit hash.

        Returns:
            Commit hash or None if unavailable
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        return None
