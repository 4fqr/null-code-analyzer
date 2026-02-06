"""
Git integration utilities
Scan only changed files vs last commit
"""

import subprocess
from pathlib import Path
from typing import List, Optional


class GitDiff:
    """Git integration for differential scanning"""

    def __init__(self, repo_path: str):
        """
        Initialize Git integration
        
        Args:
            repo_path: Path to git repository
        """
        self.repo_path = Path(repo_path)

    def is_git_repo(self) -> bool:
        """Check if directory is a git repository"""
        return (self.repo_path / ".git").exists()

    def get_changed_files(
        self,
        base_ref: str = "HEAD~1",
        target_ref: str = "HEAD",
        include_untracked: bool = False
    ) -> List[str]:
        """
        Get list of changed files between refs
        
        Args:
            base_ref: Base git ref (default: HEAD~1)
            target_ref: Target git ref (default: HEAD)
            include_untracked: Include untracked files
            
        Returns:
            List of changed file paths
        """
        if not self.is_git_repo():
            return []

        changed_files = []

        try:
            # Get modified/added files between commits
            result = subprocess.run(
                ["git", "diff", "--name-only", base_ref, target_ref],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            changed_files.extend(result.stdout.strip().split('\n'))

            # Get staged files
            result = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            staged = result.stdout.strip().split('\n')
            changed_files.extend([f for f in staged if f])

            # Get untracked files if requested
            if include_untracked:
                result = subprocess.run(
                    ["git", "ls-files", "--others", "--exclude-standard"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                untracked = result.stdout.strip().split('\n')
                changed_files.extend([f for f in untracked if f])

        except subprocess.CalledProcessError:
            return []

        # Remove duplicates and empty strings
        changed_files = list(set([f for f in changed_files if f]))
        
        # Convert to absolute paths
        return [str(self.repo_path / f) for f in changed_files]

    def get_current_branch(self) -> Optional[str]:
        """Get current git branch name"""
        if not self.is_git_repo():
            return None

        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def get_last_commit_message(self) -> Optional[str]:
        """Get last commit message"""
        if not self.is_git_repo():
            return None

        try:
            result = subprocess.run(
                ["git", "log", "-1", "--pretty=%B"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
