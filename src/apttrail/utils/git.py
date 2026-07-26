"""
Git operations utilities for APTtrail.

Handles repository management, blame operations, and commit metadata extraction.
"""

import re
import subprocess
from datetime import datetime, timezone
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
    HISTORY_TIMEOUT: int = 300  # Full-history walks are slow on large repos
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

    def get_file_last_commit_time(self, filepath: Path) -> datetime | None:
        """
        Get the last commit time for a single file.

        Prefer :meth:`get_last_commit_times` when looking up many files: this
        method walks the whole history once per call.

        Args:
            filepath: Path to the file

        Returns:
            Datetime of the last commit touching the file, or None if unavailable.
            Never falls back to the current time - a wall-clock fallback would
            make the exported feed non-deterministic and churn on every run.
        """
        try:
            relative_path = filepath.relative_to(self.repo_path)
            result = subprocess.run(
                ["git", "log", "-1", "--format=%aI", "--", str(relative_path)],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                return datetime.fromisoformat(result.stdout.strip())
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            pass
        return None

    def get_last_commit_times(self, directory: Path) -> dict[str, datetime]:
        """
        Get the last commit time for every file under a directory in one pass.

        Runs a single ``git log --name-only`` walk instead of one ``git log`` per
        file, which is both far faster and immune to the per-file timeouts that
        previously caused most lookups to fail.

        Args:
            directory: Directory inside the repository to inspect

        Returns:
            Mapping of repo-relative POSIX path to the datetime of the most
            recent commit touching that path. Files with no history are absent.
        """
        try:
            relative_dir = directory.relative_to(self.repo_path)
            result = subprocess.run(
                ["git", "log", "--format=%aI", "--name-only", "--no-renames", "--", str(relative_dir)],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=self.HISTORY_TIMEOUT,
            )
            if result.returncode != 0:
                return {}
            return self.parse_log_name_only(result.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as e:
            print(f"Warning: Could not read commit times for {directory}: {e}")
            return {}

    @staticmethod
    def parse_log_name_only(output: str) -> dict[str, datetime]:
        """
        Parse ``git log --format=%aI --name-only`` output.

        The log is ordered newest-first, so the first time a path is seen is its
        most recent commit.

        Args:
            output: Raw stdout of the git log command

        Returns:
            Mapping of repo-relative path to last commit datetime
        """
        times: dict[str, datetime] = {}
        current: datetime | None = None

        for raw_line in output.split("\n"):
            line = raw_line.strip()
            if not line:
                continue

            # A date line starts a new commit block; anything else is a path.
            try:
                current = datetime.fromisoformat(line)
                continue
            except ValueError:
                pass

            if current is not None and line not in times:
                times[line] = current

        return times

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

            timestamps = self.parse_blame_porcelain(result.stdout)

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as e:
            print(f"Warning: Could not get timestamps for {filepath.name}: {e}")

        return timestamps

    @staticmethod
    def parse_blame_porcelain(output: str) -> dict[str, dict[str, Any]]:
        """
        Parse ``git blame --line-porcelain`` output.

        Args:
            output: Raw stdout of the git blame command

        Returns:
            Mapping of line content to {first_seen, commit}
        """
        timestamps: dict[str, dict[str, Any]] = {}
        current_commit: str | None = None
        current_timestamp: datetime | None = None

        for line in output.split("\n"):
            # Content lines are prefixed with a tab; every other non-empty line
            # is a header. The header checks must be ordered most-specific
            # first - a generic "<sha> <lineno>" branch placed first would
            # swallow "author-time" and leave every timestamp unset.
            if line.startswith("\t"):
                content = line[1:].strip()
                if content and not content.startswith("#") and current_timestamp and current_commit:
                    timestamps[content] = {
                        "first_seen": current_timestamp,
                        "commit": current_commit,
                    }
            elif line.startswith("author-time "):
                unix_time = int(line.split()[1])
                # UTC keeps output independent of the runner's timezone.
                current_timestamp = datetime.fromtimestamp(unix_time, tz=timezone.utc)
            elif line:
                parts = line.split(" ", 1)
                if len(parts) == 2 and len(parts[0]) == 40:  # SHA1 hash
                    current_commit = parts[0]

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
