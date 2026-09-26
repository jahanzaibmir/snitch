"""
Snitch - Secret Detection Engine (public API)
"""

from .patterns import PATTERNS
from .entropy import shannon_entropy, classify_entropy, is_placeholder
from .scanner import scan_line, scan_file, scan_directory, build_report, make_finding
from .git_scanner import GIT_AVAILABLE, clone_repo, scan_git_history, scan_repo_full

__all__ = [
    "PATTERNS", "shannon_entropy", "classify_entropy", "is_placeholder",
    "scan_line", "scan_file", "scan_directory", "build_report", "make_finding",
    "GIT_AVAILABLE", "clone_repo", "scan_git_history", "scan_repo_full",
]

__version__ = "1.1.0"
