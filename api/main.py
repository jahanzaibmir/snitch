"""
Snitch — FastAPI Backend
Endpoints: scan URL, scan upload, fetch report, SSE progress
"""

import os
import sys
import uuid
import json
import shutil
import asyncio
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import scan_directory, scan_repo_full

# ── App setup ─────────────────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).resolve().parent.parent
UPLOADS_DIR  = BASE_DIR / "uploads"
REPORTS_DIR  = BASE_DIR / "reports"
STATIC_DIR   = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Snitch", version="1.0.0")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# In-memory scan status store (replace with Redis for production)
scan_status: dict[str, dict] = {}


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse("report.html", {"request": request, "scan_id": scan_id})


# ── Scan: GitHub URL ──────────────────────────────────────────────────────────

@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    if not url.startswith(("https://github.com", "https://gitlab.com", "http://github.com")):
        raise HTTPException(status_code=400, detail="Only GitHub/GitLab URLs are supported")

    scan_id = str(uuid.uuid4())[:8]
    scan_status[scan_id] = {
        "status": "queued",
        "stage": "Starting...",
        "progress": 0,
        "source": url,
        "started_at": datetime.now().isoformat(),
    }

    asyncio.create_task(_run_url_scan(scan_id, url))
    return {"scan_id": scan_id}


async def _run_url_scan(scan_id: str, url: str):
    try:
        scan_status[scan_id]["status"] = "running"

        def progress(stage, current, done, total):
            pct = int((done / total * 100)) if total > 0 else 0
            scan_status[scan_id].update({
                "stage": current,
                "progress": pct,
                "status": "running",
            })

        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, lambda: scan_repo_full(url, progress_callback=progress)
        )

        _save_report(scan_id, report)
        scan_status[scan_id].update({
            "status": "done",
            "progress": 100,
            "stage": "Complete",
            "finished_at": datetime.now().isoformat(),
        })

    except Exception as e:
        scan_status[scan_id].update({"status": "error", "error": str(e)})


# ── Scan: ZIP Upload ──────────────────────────────────────────────────────────

@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    scan_id = str(uuid.uuid4())[:8]
    scan_status[scan_id] = {
        "status": "queued",
        "stage": "Uploading...",
        "progress": 0,
        "source": file.filename,
        "started_at": datetime.now().isoformat(),
    }

    # Save upload
    upload_path = UPLOADS_DIR / f"{scan_id}.zip"
    with open(upload_path, "wb") as f:
        content = await file.read()
        f.write(content)

    asyncio.create_task(_run_upload_scan(scan_id, upload_path))
    return {"scan_id": scan_id}


async def _run_upload_scan(scan_id: str, zip_path: Path):
    extract_dir = UPLOADS_DIR / scan_id
    try:
        scan_status[scan_id].update({"status": "running", "stage": "Extracting archive..."})

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)

        scan_status[scan_id]["stage"] = "Scanning files..."

        def progress(current_file, files_done, files_total):
            pct = int(files_done / files_total * 100) if files_total > 0 else 0
            scan_status[scan_id].update({
                "stage": f"Scanning {current_file}",
                "progress": min(pct, 95),
            })

        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, lambda: scan_directory(str(extract_dir), progress_callback=progress)
        )

        _save_report(scan_id, report)
        scan_status[scan_id].update({
            "status": "done",
            "progress": 100,
            "stage": "Complete",
            "finished_at": datetime.now().isoformat(),
        })

    except zipfile.BadZipFile:
        scan_status[scan_id].update({"status": "error", "error": "Invalid or corrupted ZIP file"})
    except Exception as e:
        scan_status[scan_id].update({"status": "error", "error": str(e)})
    finally:
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)


# ── Status & Report endpoints ──────────────────────────────────────────────────

@app.get("/api/status/{scan_id}")
async def get_status(scan_id: str):
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_status[scan_id]


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/report/{scan_id}/download/json")
async def download_json(scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        path=str(report_path),
        filename=f"snitch-report-{scan_id}.json",
        media_type="application/json",
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _save_report(scan_id: str, report: dict):
    report["scan_id"] = scan_id
    report["generated_at"] = datetime.now().isoformat()
    path = REPORTS_DIR / f"{scan_id}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
