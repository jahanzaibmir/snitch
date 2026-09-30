"""
Snitch Engine v2.0 — public API
"""

from .patterns   import PATTERNS, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
from .entropy    import shannon_entropy, classify_entropy, is_placeholder, boost_severity
from .scanner    import scan_line, scan_file, scan_directory, build_report, make_finding, is_binary_file
from .git_scanner import GIT_AVAILABLE, clone_repo, scan_git_history, scan_repo_full

__version__ = "2.0.0"

__all__ = [
    "PATTERNS",
    "SEVERITY_CRITICAL", "SEVERITY_HIGH", "SEVERITY_MEDIUM", "SEVERITY_LOW",
    "shannon_entropy", "classify_entropy", "is_placeholder", "boost_severity",
    "scan_line", "scan_file", "scan_directory", "build_report", "make_finding",
    "is_binary_file",
    "GIT_AVAILABLE", "clone_repo", "scan_git_history", "scan_repo_full",
]
