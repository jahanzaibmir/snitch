"""
Snitch 


Snitch 
"""

import os
import re
import tempfile
import shutil
from pathlib import Path

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from .scanner import scan_line, build_report
from .patterns import SKIP_EXTENSIONS

MAX_COMMITS          = 500
CLONE_DEPTH          = MAX_COMMITS
MAX_DIFF_LINE_LEN    = 1000

_HUNK_RE   = re.compile(r'^@@.*?\+(\d+)(?:,(\d+))?')
_BINARY_RE = re.compile(r'^Binary files? .* differ$|^GIT binary patch')


#  Clone helper 
# ── Clone helper ───────────────────────────────────────────────────────────────

def clone_repo(url: str, target_dir: str) -> tuple[bool, str]:
    if not GIT_AVAILABLE:
        return False, "gitpython is not installed"
    try:
        git.Repo.clone_from(
            url, target_dir,
            depth=CLONE_DEPTH,
            no_single_branch=True,
        )
        return True, "Cloned successfully"
    except git.exc.GitCommandError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"


#  Main scanner 
# ── Main scanner ───────────────────────────────────────────────────────────────

def scan_git_history(
    repo_path: str | Path,
    progress_callback=None,
    already_found_fingerprints: set[str] | None = None,
) -> list[dict]:
    
    """
    Walk every commit in HEAD (up to MAX_COMMITS) and scan added lines.

    already_found_fingerprints: set of finding fingerprints already caught
    in the current file scan — used to skip redundant git-history findings.
    """
    if not GIT_AVAILABLE:
        return []

    known_fps: set[str] = already_found_fingerprints or set()
    findings: list[dict] = []
    repo_path = Path(repo_path).resolve()

    try:
        repo = git.Repo(str(repo_path))
    except Exception:
        return []

    try:
        commits = list(repo.iter_commits("HEAD", max_count=MAX_COMMITS))
    except Exception:
        return []

    total = len(commits)

    for idx, commit in enumerate(commits):
        if progress_callback:
            progress_callback(
                stage="git_history",
                current=f"{commit.hexsha[:8]}: {commit.message.splitlines()[0][:60]}",
                done=idx,
                total=total,
            )

        commit_meta = {
            "commit_hash":    commit.hexsha[:8],
            "commit_message": commit.message.strip()[:120],
            "commit_author":  str(commit.author),
            "commit_date":    commit.authored_datetime.isoformat(),
        }

        for file_path, patch_text in _iter_diffs(repo, commit):
            for line_no, line_text in _added_lines(patch_text):
                if len(line_text) > MAX_DIFF_LINE_LEN:
                    continue
                for finding in scan_line(line_text, line_no, file_path):
                    # Skip if we already caught this exact secret in the file scan
                    if finding["fingerprint"] in known_fps:
                        continue
                    finding["in_git_history"] = True
                    finding.update(commit_meta)
                    findings.append(finding)
                    known_fps.add(finding["fingerprint"])

    return findings


#  Diff helpers 
# ── Diff helpers ───────────────────────────────────────────────────────────────

def _iter_diffs(repo: "git.Repo", commit: "git.Commit"):
    """Yield (file_path, patch_text) for each changed file in a commit."""
    try:
        parent = commit.parents[0] if commit.parents else git.NULL_TREE
        diffs  = parent.diff(commit, create_patch=True)
    except Exception:
        return

    for diff in diffs:
        path = diff.b_path or diff.a_path
        if not path:
            continue
        if Path(path).suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            raw = diff.diff
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            if _BINARY_RE.search(text[:200]):
                continue
            yield path, text
        except Exception:
            continue


def _added_lines(patch: str):
    """
    Parse unified diff patch and yield (line_number, line_text) for added lines.
    line_number is the number in the NEW (b-side) file.
    """
    line_no = 0
    for raw_line in patch.splitlines():
        if raw_line.startswith("@@"):
            m = _HUNK_RE.search(raw_line)
            if m:
                line_no = int(m.group(1)) - 1
            continue
        if raw_line.startswith(("---", "+++")):
            continue
        if raw_line.startswith("-"):
            continue  # removed line 
            continue  # removed line — don't advance new-file counter
        line_no += 1
        if raw_line.startswith("+"):
            yield line_no, raw_line[1:]  # strip leading +


#  Full repo scan 
# ── Full repo scan (CLI / library use) ────────────────────────────────────────

def scan_repo_full(repo_url_or_path: str, progress_callback=None) -> dict:
    from .scanner import scan_directory

    is_url   = repo_url_or_path.startswith(("http://", "https://", "git@"))
    temp_dir = None

    try:
        if is_url:
            temp_dir = tempfile.mkdtemp(prefix="snitch_")
            if progress_callback:
                progress_callback(stage="clone", current="Cloning…", done=0, total=1)
            ok, msg = clone_repo(repo_url_or_path, temp_dir)
            if not ok:
                return {"error": f"Clone failed: {msg}", "findings": [], "summary": {}}
            repo_path = temp_dir
        else:
            repo_path = repo_url_or_path

        file_report = scan_directory(repo_path, progress_callback=progress_callback)

        file_fps = {f["fingerprint"] for f in file_report["findings"]}
        git_findings = scan_git_history(
            repo_path,
            progress_callback=progress_callback,
            already_found_fingerprints=file_fps,
        )

        merged = build_report(
            findings=file_report["findings"] + git_findings,
            files_scanned=file_report["stats"]["files_scanned"],
            files_skipped=file_report["stats"]["files_skipped"],
            files_total=file_report["stats"]["files_total"],
            bytes_scanned=file_report["stats"].get("bytes_scanned", 0),
            source=repo_url_or_path,
        )
        merged["git_commits_scanned"] = MAX_COMMITS
        return merged

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
