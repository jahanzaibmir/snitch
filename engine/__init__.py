"""
Snitch Engine
-------------
Public API for the scanner engine.

Usage:
    from engine import scan_directory, scan_repo_full

    # Scan a local directory
    report = scan_directory("/path/to/project")

    # Scan a GitHub repo (clones, scans files + git history)
    report = scan_repo_full("https://github.com/user/repo")
"""

from .scanner import scan_directory, scan_file, scan_line
from .git_scanner import scan_repo_full, clone_repo, scan_git_history
from .entropy import shannon_entropy, classify_entropy, is_placeholder
from .patterns import PATTERNS, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

__all__ = [
    "scan_directory",
    "scan_file",
    "scan_line",
    "scan_repo_full",
    "clone_repo",
    "scan_git_history",
    "shannon_entropy",
    "classify_entropy",
    "is_placeholder",
    "PATTERNS",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
]
