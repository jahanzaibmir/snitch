"""
Snitch — API Server

FastAPI backend that powers the Snitch UI:
  • serves the landing + report pages (rendered through Jinja2)
  • runs scans in background threads
  • streams live progress to the UI
  • persists finished reports to reports/ (they survive restarts)
"""

import json
import re
import shutil
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from engine import build_report, scan_directory, scan_line
from engine.git_scanner import GIT_AVAILABLE, clone_repo, scan_git_history
from engine.scanner import is_binary_file

# ── Paths & config ───────────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).resolve().parent.parent
STATIC_DIR   = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOADS_DIR  = BASE_DIR / "uploads"
REPORTS_DIR  = BASE_DIR / "reports"

UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_DIRECT_LINE  = 10_000              # skip absurdly long lines in single-file scans
SCAN_ID_RE       = re.compile(r"^[a-f0-9]{12}$")

app = FastAPI(title="Snitch", version="1.1.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# ── Scan registry (status in memory, reports on disk) ────────────────────────

SCANS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update(scan_id: str, **fields) -> None:
    with _LOCK:
        rec = SCANS.get(scan_id)
        if rec is not None:
            rec.update(fields)


def _new_scan(source: str, source_type: str) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with _LOCK:
        SCANS[scan_id] = {
            "scan_id": scan_id,
            "status": "queued",
            "source": source,
            "source_type": source_type,
            "stage": "queued",
            "message": "Queued…",
            "progress": 0,
            "error": None,
            "created_at": _now(),
            "completed_at": None,
        }
    return scan_id


def _forget_scan(scan_id: str) -> None:
    with _LOCK:
        SCANS.pop(scan_id, None)


def _report_path(scan_id: str) -> Path:
    return REPORTS_DIR / f"{scan_id}.json"


def _save_report(scan_id: str, report: dict) -> None:
    report["scan_id"] = scan_id
    report["generated_at"] = _now()
    _report_path(scan_id).write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _load_report(scan_id: str) -> dict | None:
    path = _report_path(scan_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _to_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def make_progress_callback(scan_id: str, has_git: bool = False):
    """
    The engine reports progress with two slightly different keyword shapes
    (file scan vs git history). Normalise both into a single 0-100 % scale.
    """
    ranges = (
        {"clone": (0, 6), "files": (6, 68), "git_history": (68, 100)}
        if has_git
        else {"files": (8, 100)}
    )

    def cb(**kw) -> None:
        stage = kw.get("stage", "files")
        message = kw.get("current") or kw.get("current_file") or "Scanning…"
        done = _to_int(kw.get("done", kw.get("files_done")))
        total = _to_int(kw.get("total", kw.get("files_total")))
        lo, hi = ranges.get(stage, (8, 100))
        frac = (done / total) if total else 0.0
        _update(scan_id, stage=stage, message=str(message)[:140],
                progress=max(1, min(lo + int(frac * (hi - lo)), 99)))

    return cb


# ── Scan runners (background threads) ────────────────────────────────────────

def _run_url_scan(scan_id: str, url: str, display_name: str) -> None:
    temp_dir = None
    try:
        if not GIT_AVAILABLE:
            raise RuntimeError("gitpython is not installed — cannot clone repositories. Run scripts\\setup.bat.")

        _update(scan_id, status="running", stage="clone",
                message="Cloning repository…", progress=2)

        temp_dir = tempfile.mkdtemp(prefix="snitch_")
        ok, msg = clone_repo(url, temp_dir)
        if not ok:
            raise RuntimeError(f"Could not clone repository: {msg}")

        cb = make_progress_callback(scan_id, has_git=True)
        file_report = scan_directory(temp_dir, progress_callback=cb)
        file_fps = {f["fingerprint"] for f in file_report["findings"]}
        git_findings = scan_git_history(temp_dir, progress_callback=cb, already_found_fingerprints=file_fps)

        report = build_report(
            findings=file_report["findings"] + git_findings,
            files_scanned=file_report["stats"]["files_scanned"],
            files_skipped=file_report["stats"]["files_skipped"],
            files_total=file_report["stats"]["files_total"],
            source=display_name,
        )
        report["git_history_scanned"] = True

        _save_report(scan_id, report)
        _update(scan_id, status="completed", stage="done",
                message="Scan complete", progress=100, completed_at=_now())
    except Exception as exc:
        _update(scan_id, status="failed", error=str(exc)[:300], completed_at=_now())
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _scan_single_file(path: Path, display_name: str, cb) -> dict:
    """Scan one uploaded file directly (bypasses the engine's extension skip rules,
    so an uploaded secrets.txt or config.md is still scanned)."""
    findings: list[dict] = []
    if not is_binary_file(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                if len(line) > MAX_DIRECT_LINE:
                    continue
                findings.extend(scan_line(line, line_no, display_name))
    cb(stage="files", current=display_name, done=1, total=1)
    return build_report(findings=findings, files_scanned=1, files_skipped=0, files_total=1, source=display_name)


def _run_upload_scan(scan_id: str, work_root: Path, scan_dir: Path,
                     single_file: Path | None, display_name: str) -> None:
    try:
        if single_file is not None:
            cb = make_progress_callback(scan_id, has_git=False)
            _update(scan_id, status="running", stage="files",
                    message="Scanning file…", progress=5)
            report = _scan_single_file(single_file, display_name, cb)
        else:
            has_git = GIT_AVAILABLE and (scan_dir / ".git").exists()
            cb = make_progress_callback(scan_id, has_git=has_git)
            _update(scan_id, status="running", stage="files",
                    message="Scanning files…", progress=8)

            file_report = scan_directory(scan_dir, progress_callback=cb)
            git_findings = []
            if has_git:
                git_fps = {f["fingerprint"] for f in file_report["findings"]}
                git_findings = scan_git_history(scan_dir, progress_callback=cb, already_found_fingerprints=git_fps)

            report = build_report(
                findings=file_report["findings"] + git_findings,
                files_scanned=file_report["stats"]["files_scanned"],
                files_skipped=file_report["stats"]["files_skipped"],
                files_total=file_report["stats"]["files_total"],
                source=display_name,
            )
            report["git_history_scanned"] = has_git

        _save_report(scan_id, report)
        _update(scan_id, status="completed", stage="done",
                message="Scan complete", progress=100, completed_at=_now())
    except Exception as exc:
        _update(scan_id, status="failed", error=str(exc)[:300], completed_at=_now())
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _validate_repo_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise HTTPException(400, "Please enter a repository URL.")
    if url.startswith("git@"):
        return url.rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "That doesn't look like a valid repository URL.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "URLs with embedded credentials are not allowed.")
    return url.rstrip("/")


def _pretty_repo_name(url: str) -> str:
    name = url
    if "://" in name:
        name = name.split("://", 1)[1]
    if name.startswith("git@"):
        name = name.split("@", 1)[1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or url


def _safe_extract_zip(zip_path: Path, target: Path) -> None:
    """Extract a zip while blocking path-traversal (zip-slip) attacks."""
    target = target.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            dest = (target / member.filename).resolve()
            if not dest.is_relative_to(target):
                raise ValueError("Archive contains unsafe paths (zip-slip) — refusing to extract.")
        zf.extractall(target)


# ── Routes ───────────────────────────────────────────────────────────────────

class ScanUrlBody(BaseModel):
    url: str


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report/{scan_id}")
async def report_page(request: Request, scan_id: str):
    # NOTE: this MUST go through Jinja2Templates — that's what injects the
    # scan_id into the page. Serving report.html as a static file is exactly
    # what produced the blank report page.
    if not SCAN_ID_RE.fullmatch(scan_id):
        return RedirectResponse("/", status_code=303)
    with _LOCK:
        known = scan_id in SCANS
    if not known and not _report_path(scan_id).exists():
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("report.html", {"request": request, "scan_id": scan_id})


@app.post("/api/scan/url")
async def start_url_scan(body: ScanUrlBody):
    url = _validate_repo_url(body.url)
    scan_id = _new_scan(source=url, source_type="url")
    threading.Thread(target=_run_url_scan, args=(scan_id, url, _pretty_repo_name(url)),
                     daemon=True, name=f"snitch-{scan_id}").start()
    return {"scan_id": scan_id, "status_url": f"/api/status/{scan_id}",
            "report_url": f"/report/{scan_id}"}


@app.post("/api/scan/upload")
async def start_upload_scan(file: UploadFile = File(...)):
    safe_name = Path(file.filename or "").name
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(400, "Invalid file name.")

    scan_id = _new_scan(source=safe_name, source_type="upload")
    work_root = UPLOADS_DIR / scan_id
    scan_dir = work_root / "payload"
    work_root.mkdir(parents=True)
    scan_dir.mkdir()
    upload_path = work_root / "upload.bin"

    single: Path | None = None
    try:
        size = 0
        with open(upload_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "File exceeds the 50 MB limit.")
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "The uploaded file is empty.")

        if safe_name.lower().endswith(".zip"):
            _safe_extract_zip(upload_path, scan_dir)
        else:
            single = scan_dir / safe_name
            shutil.move(str(upload_path), str(single))
    except HTTPException:
        shutil.rmtree(work_root, ignore_errors=True)
        _forget_scan(scan_id)
        raise
    except zipfile.BadZipFile:
        shutil.rmtree(work_root, ignore_errors=True)
        _forget_scan(scan_id)
        raise HTTPException(400, "That file is not a valid ZIP archive.")
    except Exception as exc:
        shutil.rmtree(work_root, ignore_errors=True)
        _forget_scan(scan_id)
        raise HTTPException(400, f"Could not process the upload: {exc}")

    threading.Thread(target=_run_upload_scan,
                     args=(scan_id, work_root, scan_dir, single, safe_name),
                     daemon=True, name=f"snitch-{scan_id}").start()
    return {"scan_id": scan_id, "status_url": f"/api/status/{scan_id}",
            "report_url": f"/report/{scan_id}"}


@app.get("/api/status/{scan_id}")
async def scan_status(scan_id: str):
    with _LOCK:
        rec = SCANS.get(scan_id)
        snapshot = dict(rec) if rec else None
    if snapshot is not None:
        return snapshot
    # Server may have restarted — a finished report still lives on disk.
    if _report_path(scan_id).exists():
        return {"scan_id": scan_id, "status": "completed", "stage": "done",
                "message": "Scan complete", "progress": 100}
    raise HTTPException(404, "Scan not found.")


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    report = _load_report(scan_id)
    if report is None:
        raise HTTPException(404, "Report not found or not ready yet.")
    return report


@app.get("/api/report/{scan_id}/download/json")
async def download_report_json(scan_id: str):
    path = _report_path(scan_id)
    if not path.exists():
        raise HTTPException(404, "Report not found.")
    return FileResponse(path, media_type="application/json",
                        filename=f"snitch-report-{scan_id}.json")


@app.get("/api/health")
async def health():
    with _LOCK:
        active = sum(1 for r in SCANS.values() if r["status"] in ("queued", "running"))
    return {"status": "ok", "version": app.version,
            "git_support": GIT_AVAILABLE, "active_scans": active}