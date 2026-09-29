"""
Snitch — File Scanner
Walks a directory or file, applies patterns, entropy checks, false positive filters.
Returns structured findings.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Generator

from .patterns import (
    PATTERNS,
    PLACEHOLDER_PATTERNS,
    SKIP_EXTENSIONS,
    SKIP_PATHS,
    SKIP_FILENAMES,
)
from .entropy import classify_entropy, is_placeholder, boost_severity


MAX_FILE_SIZE_MB = 5
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Lines that are clearly comments in common languages  still scan them
# but flag findings in comments with lower confidence
COMMENT_PREFIXES = ('#', '//', '--', '*', '/*', '"""', "'''")

 
# Finding model


def make_finding(
    pattern_id: str,
    pattern_name: str,
    category: str,
    severity: str,
    file_path: str,
    line_number: int,
    line_content: str,
    matched_value: str,
    entropy: dict,
    remediation: str,
    in_comment: bool = False,
    in_git_history: bool = False,
    commit_hash: str = None,
    commit_message: str = None,
) -> dict:
    """Build a standardised finding dict."""
    
    # Redact the matched value for display — show first 4 and last 4 chars
    redacted = _redact(matched_value)
    
    # Adjust severity based on entropy
    final_severity = boost_severity(severity, entropy["label"])
    
    # If found in a comment, nudge severity down one step unless it's a key pattern
    if in_comment and final_severity not in ("CRITICAL",):
        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx = sev_order.index(final_severity)
        final_severity = sev_order[max(0, idx - 1)]

    return {
        "id": str(uuid.uuid4()),
        "pattern_id": pattern_id,
        "name": pattern_name,
        "category": category,
        "severity": final_severity,
        "file": file_path,
        "line": line_number,
        "line_content": line_content.rstrip(),
        "matched_value": matched_value,
        "redacted_value": redacted,
        "entropy": entropy,
        "remediation": remediation,
        "in_comment": in_comment,
        "in_git_history": in_git_history,
        "commit_hash": commit_hash,
        "commit_message": commit_message,
    }


def _redact(value: str) -> str:
    """Partially redact a secret for safe display."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "•" * (len(value) - 8) + value[-4:]


 
# File filtering


def should_skip_path(path: Path) -> bool:
    """Return True if this file/directory should be skipped entirely."""
    parts = set(path.parts)
    
    # Skip blacklisted directory names
    if parts & SKIP_PATHS:
        return True
    
    # Skip blacklisted filenames
    if path.name in SKIP_FILENAMES:
        return True
    
    # Skip by extension
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return True
    
    # Skip minified JS/CSS
    if path.name.endswith(('.min.js', '.min.css', '.bundle.js')):
        return True
    
    return False


def is_binary_file(file_path: Path) -> bool:
    """Quick binary check by reading first 1024 bytes."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\x00' in chunk
    except Exception:
        return True



# Line level scanner


def scan_line(line: str, line_number: int, file_path: str) -> list[dict]:
    """Scan a single line against all patterns. Returns list of findings."""
    findings = []
    stripped = line.strip()
    
    # Detect if this line is a comment
    in_comment = any(stripped.startswith(prefix) for prefix in COMMENT_PREFIXES)
    
    for pattern in PATTERNS:
        matches = pattern["regex"].finditer(line)
        for match in matches:
            # Get the captured group if it exists, else the full match
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            
            if not value or len(value) < 6:
                continue
            
            # Check placeholder patterns
            if is_placeholder(value):
                continue
            
            placeholder_match = any(p.search(value) for p in PLACEHOLDER_PATTERNS)
            if placeholder_match:
                continue
            
            # Entropy analysis
            entropy = classify_entropy(value)
            
            # For generic patterns, require at least medium entropy
            if pattern["id"] in ("generic_api_key", "generic_token", "generic_password"):
                if not entropy["is_likely_real"]:
                    continue
            
            finding = make_finding(
                pattern_id=pattern["id"],
                pattern_name=pattern["name"],
                category=pattern["category"],
                severity=pattern["severity"],
                file_path=file_path,
                line_number=line_number,
                line_content=line,
                matched_value=value,
                entropy=entropy,
                remediation=pattern["remediation"],
                in_comment=in_comment,
            )
            findings.append(finding)
    
    return findings



# File scanner


def scan_file(file_path: Path, base_dir: Path) -> list[dict]:
    """Scan a single file. Returns all findings."""
    findings = []
    
    if should_skip_path(file_path):
        return findings
    
    if not file_path.is_file():
        return findings
    
    # Skip large files
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return findings
    except OSError:
        return findings
    
    if is_binary_file(file_path):
        return findings
    
    # Relative path for display
    try:
        display_path = str(file_path.relative_to(base_dir))
    except ValueError:
        display_path = str(file_path)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_number, line in enumerate(f, start=1):
                line_findings = scan_line(line, line_number, display_path)
                findings.extend(line_findings)
    except (PermissionError, OSError):
        pass
    
    return findings



# Directory scanner


def scan_directory(
    directory: str | Path,
    progress_callback=None
) -> dict:
    """
    Scan an entire directory recursively.
    
    progress_callback: optional callable(current_file: str, files_done: int, files_total: int)
    Returns a scan result dict.
    """
    base_dir = Path(directory).resolve()
    
    if not base_dir.exists():
        raise FileNotFoundError(f"Directory not found: {base_dir}")
    
    # Collect all files first for progress tracking
    all_files = []
    for root, dirs, files in os.walk(base_dir):
        root_path = Path(root)
        
        # Prune directories in-place (skip node_modules etc. at dir level)
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_PATHS and not d.startswith('.')
        ]
        
        for fname in files:
            all_files.append(root_path / fname)
    
    total_files = len(all_files)
    all_findings = []
    files_scanned = 0
    files_skipped = 0
    
    for i, file_path in enumerate(all_files):
        if should_skip_path(file_path):
            files_skipped += 1
            continue
        
        findings = scan_file(file_path, base_dir)
        all_findings.extend(findings)
        files_scanned += 1
        
        if progress_callback:
            progress_callback(
                current_file=str(file_path.relative_to(base_dir)),
                files_done=i + 1,
                files_total=total_files,
            )
    
    return build_report(all_findings, files_scanned, files_skipped, total_files, str(base_dir))



# Report builder


def build_report(
    findings: list[dict],
    files_scanned: int,
    files_skipped: int,
    files_total: int,
    source: str,
) -> dict:
    """Build the final structured report from raw findings."""
    
    # Deduplicate — same pattern + same value in same file/line
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["pattern_id"], f["file"], f["line"], f["redacted_value"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    # Summary counts
    summary = {
        "total": len(unique_findings),
        "critical": sum(1 for f in unique_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in unique_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in unique_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in unique_findings if f["severity"] == "LOW"),
    }
    
    # Category breakdown
    categories = {}
    for f in unique_findings:
        cat = f["category"]
        categories[cat] = categories.get(cat, 0) + 1
    
    return {
        "source": source,
        "summary": summary,
        "categories": categories,
        "stats": {
            "files_total": files_total,
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
        },
        "findings": unique_findings,
    }
