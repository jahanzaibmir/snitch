"""
Snitch — Git History Scanner
Scans git commit history for secrets that may have been introduced and later removed.
Uses gitpython to walk commits and scan diffs.
"""

import os
import tempfile
from pathlib import Path

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from .scanner import scan_line, build_report
from .patterns import SKIP_EXTENSIONS


MAX_COMMITS = 500          # Don't walk more than this many commits
MAX_DIFF_LINE_LENGTH = 500 # Skip extremely long lines in diffs (minified code)


def clone_repo(url: str, target_dir: str) -> tuple[bool, str]:
    """
    Clone a remote git repo to target_dir.
    Returns (success: bool, message: str)
    """
    if not GIT_AVAILABLE:
        return False, "gitpython not installed"
    
    try:
        git.Repo.clone_from(url, target_dir, depth=100)  # shallow clone, last 100 commits
        return True, "Cloned successfully"
    except git.exc.GitCommandError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"


def scan_git_history(repo_path: str | Path, progress_callback=None) -> list[dict]:
    """
    Walk git commit history and scan each commit's diff for secrets.
    Returns list of findings (with commit metadata attached).
    """
    if not GIT_AVAILABLE:
        return []
    
    findings = []
    repo_path = Path(repo_path).resolve()
    
    try:
        repo = git.Repo(str(repo_path))
    except git.exc.InvalidGitRepositoryError:
        return []
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
        
        try:
            diff_text = _get_commit_diff(repo, commit)
        except Exception:
            continue
        
        if not diff_text:
            continue
        
        for line_number, line in enumerate(diff_text.splitlines(), start=1):
            # Only scan added lines (lines starting with '+', not '+++')
            if not line.startswith('+') or line.startswith('+++'):
                continue
            
            # Strip the leading '+' for scanning
            actual_line = line[1:]
            
            if len(actual_line) > MAX_DIFF_LINE_LENGTH:
                continue
            
            line_findings = scan_line(actual_line, line_number, f"[git:{commit.hexsha[:8]}]")
            
            for f in line_findings:
                f["in_git_history"] = True
                f["commit_hash"] = commit.hexsha[:8]
                f["commit_message"] = commit.message.strip()[:120]
                f["commit_author"] = str(commit.author)
                f["commit_date"] = commit.authored_datetime.isoformat()
            
            findings.extend(line_findings)
    
    return findings


def _get_commit_diff(repo: 'git.Repo', commit: 'git.Commit') -> str:
    """Get the diff text for a commit."""
    try:
        if commit.parents:
            diffs = commit.parents[0].diff(commit, create_patch=True)
        else:
            # Initial commit — diff against empty tree
            diffs = commit.diff(git.NULL_TREE, create_patch=True)
        
        diff_parts = []
        for diff in diffs:
            # Skip binary and skippable extensions
            if diff.b_path:
                ext = Path(diff.b_path).suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
            
            try:
                if diff.diff:
                    diff_parts.append(diff.diff.decode('utf-8', errors='replace'))
            except Exception:
                continue
        
        return '\n'.join(diff_parts)
    except Exception:
        return ""


def scan_repo_full(
    repo_url_or_path: str,
    progress_callback=None,
) -> dict:
    """
    Full repo scan: clone (if URL), scan files, scan git history.
    Returns merged report.
    """
    from .scanner import scan_directory
    import shutil
    
    is_url = repo_url_or_path.startswith(('http://', 'https://', 'git@'))
    
    temp_dir = None
    try:
        if is_url:
            temp_dir = tempfile.mkdtemp(prefix='snitch_')
            if progress_callback:
                progress_callback(stage="clone", current="Cloning repository...", done=0, total=1)
            
            success, msg = clone_repo(repo_url_or_path, temp_dir)
            if not success:
                return {"error": f"Clone failed: {msg}", "findings": [], "summary": {}}
            
            repo_path = temp_dir
        else:
            repo_path = repo_url_or_path
        
        # Phase 1: scan current files
        if progress_callback:
            progress_callback(stage="files", current="Scanning files...", done=0, total=1)
        
        file_report = scan_directory(repo_path, progress_callback=None)
        
        # Phase 2: scan git history
        if progress_callback:
            progress_callback(stage="git_history", current="Scanning git history...", done=0, total=1)
        
        git_findings = scan_git_history(repo_path, progress_callback=progress_callback)
        
        # Merge findings
        all_findings = file_report["findings"] + git_findings
        
        merged_report = build_report(
            findings=all_findings,
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
