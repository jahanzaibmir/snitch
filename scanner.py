"""
Snitch — File Scanner v2.0

Improvements over v1:
- .txt, .md, .env files are NOW scanned (they often contain real secrets)
- Context window: stores surrounding lines so findings show meaningful context
- Per-finding confidence combining pattern + entropy
- Cross-file deduplication uses value fingerprint, not redacted string
- Detects .env variable assignments (KEY=VALUE without quotes)
- Skips lines that are clearly URL parameters / docs references
- Max file size raised to 10 MB for large config files
- Scan stats include bytes_scanned
"""

import os
import re
import uuid
import hashlib
from pathlib import Path

from .patterns import (
    PATTERNS,
    PLACEHOLDER_PATTERNS,
    SKIP_EXTENSIONS,
    SKIP_PATHS,
    SKIP_FILENAMES,
)
from .entropy import classify_entropy, is_placeholder, boost_severity

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024   # 10 MB
CONTEXT_LINES       = 2                  # lines before/after a finding
MAX_LINE_LENGTH     = 2000               # skip minified / data lines

COMMENT_PREFIXES = ('#', '//', '--', '/*', '*', '"""', "'''", '<!--', ';')

# ENV file pattern: KEY=value (unquoted)
_ENV_RE = re.compile(r'^([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$')

# Lines that look like documentation references (not real secrets)
_DOC_LINE_RE = re.compile(
    r'(?i)(e\.g\.|example|see |refer to|docs?:|note:|https?://docs\.|# ?TODO|# ?FIXME)'
)


# ── Finding model ──────────────────────────────────────────────────────────────

def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    keep = min(4, len(value) // 5)
    return value[:keep] + "•" * (len(value) - keep * 2) + value[-keep:]


def _fingerprint(value: str) -> str:
    """SHA-256 of the raw value — used for deduplication across files."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def make_finding(
    *,
    pattern_id: str,
    pattern_name: str,
    category: str,
    severity: str,
    file_path: str,
    line_number: int,
    line_content: str,
    context_before: list[str],
    context_after: list[str],
    matched_value: str,
    entropy: dict,
    remediation: str,
    in_comment: bool = False,
    in_git_history: bool = False,
    commit_hash: str | None = None,
    commit_message: str | None = None,
    commit_date: str | None = None,
    commit_author: str | None = None,
) -> dict:
    return {
        "id":               str(uuid.uuid4()),
        "fingerprint":      _fingerprint(matched_value),
        "pattern_id":       pattern_id,
        "name":             pattern_name,
        "category":         category,
        "severity":         severity,
        "file":             file_path,
        "line":             line_number,
        "line_content":     line_content.rstrip(),
        "context_before":   [l.rstrip() for l in context_before],
        "context_after":    [l.rstrip() for l in context_after],
        "matched_value":    matched_value,
        "redacted_value":   _redact(matched_value),
        "entropy":          entropy,
        "remediation":      remediation,
        "in_comment":       in_comment,
        "in_git_history":   in_git_history,
        "commit_hash":      commit_hash,
        "commit_message":   commit_message,
        "commit_date":      commit_date,
        "commit_author":    commit_author,
    }


# ── Path filtering ─────────────────────────────────────────────────────────────

def should_skip_path(path: Path) -> bool:
    parts = set(path.parts)
    if parts & SKIP_PATHS:
        return True
    if path.name in SKIP_FILENAMES:
        return True
    suffix = path.suffix.lower()
    # Check composite suffixes like .min.js
    full_name = path.name.lower()
    if any(full_name.endswith(s) for s in ('.min.js', '.min.css', '.bundle.js', '.chunk.js')):
        return True
    if suffix in SKIP_EXTENSIONS:
        return True
    return False


def is_binary_file(file_path: Path) -> bool:
    try:
        with open(file_path, 'rb') as f:
            return b'\x00' in f.read(8192)
    except Exception:
        return True


# ── Line-level scanner ─────────────────────────────────────────────────────────

def scan_line(line: str, line_number: int, file_path: str,
              context_before: list[str] | None = None,
              context_after: list[str] | None = None) -> list[dict]:
    """
    Scan one line against all patterns.
    Returns a list of findings (usually 0 or 1, occasionally more).
    """
    findings: list[dict] = []

    # Quick exits
    if not line or len(line) > MAX_LINE_LENGTH:
        return findings

    stripped = line.strip()

    # Skip obvious documentation lines
    if _DOC_LINE_RE.search(stripped):
        return findings

    in_comment = any(stripped.startswith(p) for p in COMMENT_PREFIXES)

    # Try to extract unquoted env values for extra pattern coverage
    env_match = _ENV_RE.match(stripped)
    env_value_extra = env_match.group(2).strip() if env_match else None

    for pattern in PATTERNS:
        confidence = pattern.get("confidence", "medium")

        matches = list(pattern["regex"].finditer(line))

        # Also check env_value_extra if it looks long enough
        if env_value_extra and len(env_value_extra) >= 12 and not matches:
            m2 = pattern["regex"].search(env_value_extra)
            if m2:
                matches = [m2]

        for match in matches:
            value = (
                match.group(1)
                if match.lastindex and match.lastindex >= 1
                else match.group(0)
            )

            if not value or len(value) < 6:
                continue

            # Placeholder check
            if is_placeholder(value):
                continue

            # Pattern-level placeholder filters
            if any(pp.search(value) for pp in PLACEHOLDER_PATTERNS):
                continue

            # Entropy analysis
            entropy = classify_entropy(value, pattern_confidence=confidence)

            # For medium-confidence / generic patterns, require at least medium entropy
            needs_entropy = confidence == "medium" or pattern_id_is_generic(pattern["id"])
            if needs_entropy and not entropy["is_likely_real"]:
                continue

            # Compute final severity
            final_severity = boost_severity(
                pattern["severity"],
                entropy["label"],
                pattern_confidence=confidence,
            )

            # Comments slightly reduce severity (but CRITICAL stays CRITICAL)
            if in_comment and final_severity not in ("CRITICAL",):
                sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                idx = sev_order.index(final_severity)
                final_severity = sev_order[max(0, idx - 1)]

            findings.append(make_finding(
                pattern_id=pattern["id"],
                pattern_name=pattern["name"],
                category=pattern["category"],
                severity=final_severity,
                file_path=file_path,
                line_number=line_number,
                line_content=line,
                context_before=context_before or [],
                context_after=context_after or [],
                matched_value=value,
                entropy=entropy,
                remediation=pattern["remediation"],
                in_comment=in_comment,
            ))

    return findings


def pattern_id_is_generic(pid: str) -> bool:
    return pid.startswith("generic_")


# ── File scanner ───────────────────────────────────────────────────────────────

def scan_file(file_path: Path, base_dir: Path) -> list[dict]:
    if should_skip_path(file_path):
        return []
    if not file_path.is_file():
        return []
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return []
    except OSError:
        return []
    if is_binary_file(file_path):
        return []

    try:
        display_path = str(file_path.relative_to(base_dir))
    except ValueError:
        display_path = str(file_path)

    findings: list[dict] = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except (PermissionError, OSError):
        return []

    for i, line in enumerate(lines):
        before = [l for l in lines[max(0, i - CONTEXT_LINES):i]]
        after  = [l for l in lines[i + 1: i + 1 + CONTEXT_LINES]]
        hits   = scan_line(line, i + 1, display_path,
                           context_before=before, context_after=after)
        findings.extend(hits)

    return findings


# ── Directory scanner ──────────────────────────────────────────────────────────

def scan_directory(directory: str | Path, progress_callback=None) -> dict:
    base_dir = Path(directory).resolve()
    if not base_dir.exists():
        raise FileNotFoundError(f"Directory not found: {base_dir}")

    all_files: list[Path] = []
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_PATHS and not d.startswith('.')
        ]
        for fname in files:
            all_files.append(Path(root) / fname)

    total         = len(all_files)
    all_findings: list[dict] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0

    for i, fp in enumerate(all_files):
        if should_skip_path(fp):
            files_skipped += 1
        else:
            hits = scan_file(fp, base_dir)
            all_findings.extend(hits)
            files_scanned += 1
            try:
                bytes_scanned += fp.stat().st_size
            except OSError:
                pass

        if progress_callback:
            try:
                rel = str(fp.relative_to(base_dir))
            except ValueError:
                rel = str(fp)
            progress_callback(current_file=rel, files_done=i + 1, files_total=total)

    return build_report(
        findings=all_findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        files_total=total,
        bytes_scanned=bytes_scanned,
        source=str(base_dir),
    )


# ── Report builder ─────────────────────────────────────────────────────────────

def build_report(
    findings: list[dict],
    files_scanned: int,
    files_skipped: int,
    files_total: int,
    source: str,
    bytes_scanned: int = 0,
) -> dict:
    # Deduplicate by fingerprint (same raw secret value) + file + line
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in findings:
        key = (f["fingerprint"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique.sort(key=lambda x: sev_order.get(x["severity"], 4))

    summary = {
        "total":    len(unique),
        "critical": sum(1 for f in unique if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in unique if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in unique if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in unique if f["severity"] == "LOW"),
    }

    categories: dict[str, int] = {}
    for f in unique:
        cat = f["category"]
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "source":     source,
        "summary":    summary,
        "categories": categories,
        "stats": {
            "files_total":    files_total,
            "files_scanned":  files_scanned,
            "files_skipped":  files_skipped,
            "bytes_scanned":  bytes_scanned,
        },
        "findings": unique,
    }
