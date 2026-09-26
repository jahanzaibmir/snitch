"""
Snitch — Git History Scanner
Scans git commit history for secrets that may have been introduced and later removed.
Uses gitpython to walk commits and scan diffs.
"""

import os
import re
import tempfile
from pathlib import Path

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from .scanner import scan_line, build_report
from .patterns import SKIP_EXTENSIONS


MAX_COMMITS = 500            # Don't walk more than this many commits
CLONE_DEPTH = MAX_COMMITS    # FIX: was depth=100 while UI claimed 500 commits
MAX_DIFF_LINE_LENGTH = 500   # Skip extremely long lines in diffs (minified code)

_HUNK_RE = re.compile(r"^@@.*?\+(\d+)")


def clone_repo(url: str, target_dir: str) -> tuple[bool, str]:
    """Clone a remote git repo to target_dir. Returns (success, message)."""
    if not GIT_AVAILABLE:
        return False, "gitpython not installed"
    try:
        git.Repo.clone_from(url, target_dir, depth=CLONE_DEPTH)
        return True, "Cloned successfully"
    except git.exc.GitCommandError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"


def scan_git_history(repo_path: str | Path, progress_callback=None) -> list[dict]:
    """Walk git commit history and scan each commit's diff for secrets."""
    if not GIT_AVAILABLE:
        return []

    findings = []
    repo_path = Path(repo_path).resolve()

    try:
        repo = git.Repo(str(repo_path))
    except Exception:
        return []

    try:
        commits = list(repo.iter_commits('HEAD', max_count=MAX_COMMITS))
    except Exception:
        return []

    total = len(commits)

    for i, commit in enumerate(commits):
        if progress_callback:
            progress_callback(
                stage="git_history",
                current=f"Commit {commit.hexsha[:8]}: {commit.message[:60].strip()}",
                done=i,
                total=total,
            )

        # FIX: iterate per-file diffs so findings carry the REAL file path
        # and line number (parsed from @@ hunk headers), not "[git:hash]".
        for file_path, diff_text in _iter_commit_diffs(repo, commit):
            line_no = 0
            for line in diff_text.splitlines():
                if line.startswith("@@"):
                    m = _HUNK_RE.search(line)
                    line_no = int(m.group(1)) - 1 if m else 0
                    continue
                if line.startswith(("+++", "---")):
                    continue
                if line.startswith("-"):
                    continue  # removed lines don't advance the new-file counter
                line_no += 1
                if not line.startswith("+"):
                    continue  # context line — counted above, not scanned

                actual_line = line[1:]
                if len(actual_line) > MAX_DIFF_LINE_LENGTH:
                    continue

                for f in scan_line(actual_line, line_no, file_path):
                    f["in_git_history"] = True
                    f["commit_hash"] = commit.hexsha[:8]
                    f["commit_message"] = commit.message.strip()[:120]
                    f["commit_author"] = str(commit.author)
                    f["commit_date"] = commit.authored_datetime.isoformat()
                    findings.append(f)

    return findings


def _iter_commit_diffs(repo: 'git.Repo', commit: 'git.Commit'):
    """Yield (file_path, patch_text) for each changed file in a commit."""
    try:
        if commit.parents:
            diffs = commit.parents[0].diff(commit, create_patch=True)
        else:
            diffs = commit.diff(git.NULL_TREE, create_patch=True)  # initial commit
    except Exception:
        return

    for diff in diffs:
        path = diff.b_path or diff.a_path
        if not path or Path(path).suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            text = diff.diff.decode("utf-8", errors="replace") if diff.diff else ""
        except Exception:
            continue
        if text:
            yield path, text


def scan_repo_full(repo_url_or_path: str, progress_callback=None) -> dict:
    """
    Full repo scan: clone (if URL), scan files, scan git history.
    Returns merged report. (The API orchestrates these phases itself;
    this helper remains for CLI / library use.)
    """
    from .scanner import scan_directory
    import shutil

    is_url = repo_url_or_path.startswith(('http://', 'https://', 'git@'))
    temp_dir = None

    try:
        if is_url:
            temp_dir = tempfile.mkdtemp(prefix='snitch_')
            if progress_callback:
                progress_callback(stage="clone", current="Cloning repository…", done=0, total=1)

            success, msg = clone_repo(repo_url_or_path, temp_dir)
            if not success:
                return {"error": f"Clone failed: {msg}", "findings": [], "summary": {}}
            repo_path = temp_dir
        else:
            repo_path = repo_url_or_path

        if progress_callback:
            progress_callback(stage="files", current="Scanning files…", done=0, total=1)

        # FIX: was progress_callback=None — per-file progress never reached the UI
        file_report = scan_directory(repo_path, progress_callback=progress_callback)

        if progress_callback:
            progress_callback(stage="git_history", current="Scanning git history…", done=0, total=1)

        git_findings = scan_git_history(repo_path, progress_callback=progress_callback)

        merged_report = build_report(
            findings=file_report["findings"] + git_findings,
            files_scanned=file_report["stats"]["files_scanned"],
            files_skipped=file_report["stats"]["files_skipped"],
            files_total=file_report["stats"]["files_total"],
            source=repo_url_or_path,
        )
        merged_report["git_commits_scanned"] = MAX_COMMITS
        return merged_report

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)