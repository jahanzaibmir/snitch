"""
Snitch — FastAPI Backend
"""

import os, sys, uuid, json, shutil, asyncio, zipfile
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import scan_directory, scan_repo_full

# ── Setup ──────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"

UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Snitch", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Simple in-memory scan status store
scan_status: dict[str, dict] = {}

# ── Pages ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    # Serve the page even while the scan is still running.
    # The JS will call /api/status and /api/report to populate the UI.
    # Only hard-404 when this scan_id is completely unknown.
    if scan_id not in scan_status and not (REPORTS_DIR / f"{scan_id}.json").exists():
        raise HTTPException(404, "Report not found")
    return templates.TemplateResponse("report.html", {"request": request, "scan_id": scan_id})


# ── Scan: URL ──────────────────────────────────────────────────────────────
@app.post("/api/scan/url")
async def scan_url(background_tasks: BackgroundTasks, url: str = Form(...)):
    url = url.strip()
    if not (url.startswith("https://github.com") or url.startswith("https://gitlab.com")):
        raise HTTPException(400, "Only GitHub and GitLab URLs are supported")
    scan_id = uuid.uuid4().hex[:8]
    scan_status[scan_id] = {
        "status": "queued",
        "stage": "Starting…",
        "progress": 0,
        "source": url,
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_url_scan, scan_id, url)
    return {"scan_id": scan_id}


def _run_url_scan(scan_id: str, url: str):
    try:
        scan_status[scan_id]["status"] = "running"

        def cb(stage, current, done, total):
            pct = int(done / total * 100) if total > 0 else 0
            scan_status[scan_id].update({"stage": str(current)[:80], "progress": pct})

        report = scan_repo_full(url, progress_callback=cb)
        _save(scan_id, report)
        scan_status[scan_id].update({
            "status": "done",
            "progress": 100,
            "stage": "Complete",
            "finished_at": datetime.now().isoformat(),
        })
    except Exception as e:
        scan_status[scan_id].update({"status": "error", "error": str(e)})


# ── Scan: Upload ───────────────────────────────────────────────────────────
@app.post("/api/scan/upload")
async def scan_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    scan_id  = uuid.uuid4().hex[:8]
    zip_path = UPLOADS_DIR / f"{scan_id}.zip"
    content  = await file.read()
    if len(content) > 52_428_800:  # 50 MB
        raise HTTPException(400, "File exceeds 50 MB limit")
    zip_path.write_bytes(content)
    scan_status[scan_id] = {
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "source": file.filename,
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_upload_scan, scan_id, zip_path)
    return {"scan_id": scan_id}


def _run_upload_scan(scan_id: str, zip_path: Path):
    extract_dir = UPLOADS_DIR / scan_id
    try:
        scan_status[scan_id].update({
            "status": "running",
            "stage": "Extracting archive…",
            "progress": 2,
        })

        # Handle both real ZIPs and raw files wrapped by the browser JS
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            # Not a zip — treat the upload as a single plain file
            extract_dir.mkdir(parents=True, exist_ok=True)
            dest = extract_dir / (zip_path.stem or "upload")
            dest.write_bytes(zip_path.read_bytes())

        scan_status[scan_id]["stage"] = "Scanning files…"

        def cb(current_file, files_done, files_total):
            pct = min(int(files_done / files_total * 94), 94) if files_total > 0 else 0
            scan_status[scan_id].update({
                "stage": str(current_file)[:80],
                "progress": pct + 3,
            })

        report = scan_directory(str(extract_dir), progress_callback=cb)
        _save(scan_id, report)
        scan_status[scan_id].update({
            "status": "done",
            "progress": 100,
            "stage": "Complete",
            "finished_at": datetime.now().isoformat(),
        })
    except Exception as e:
        scan_status[scan_id].update({"status": "error", "error": str(e)})
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
        zip_path.unlink(missing_ok=True)


# ── API ────────────────────────────────────────────────────────────────────
@app.get("/api/status/{scan_id}")
async def get_status(scan_id: str):
    # Return live status if in memory
    if scan_id in scan_status:
        return scan_status[scan_id]
    # After a server restart the JSON may exist on disk but status is gone from memory
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            return {
                "status":      "done",
                "stage":       "Complete",
                "progress":    100,
                "source":      data.get("source", ""),
                "started_at":  data.get("generated_at", ""),
                "finished_at": data.get("generated_at", ""),
            }
        except Exception:
            pass
    raise HTTPException(404, "Scan not found")


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    p = REPORTS_DIR / f"{scan_id}.json"
    if not p.exists():
        raise HTTPException(404, "Report not found")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/report/{scan_id}/download/json")
async def download_json(scan_id: str):
    p = REPORTS_DIR / f"{scan_id}.json"
    if not p.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(
        str(p),
        filename=f"snitch-report-{scan_id}.json",
        media_type="application/json",
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Helper ─────────────────────────────────────────────────────────────────
def _save(scan_id: str, report: dict):
    report["scan_id"]      = scan_id
    report["generated_at"] = datetime.now().isoformat()
    (REPORTS_DIR / f"{scan_id}.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ── Optional PDF export ────────────────────────────────────────────────────
@app.get("/api/report/{scan_id}/download/pdf")
async def download_pdf(scan_id: str):
    from engine.pdf_report import generate_pdf, WEASYPRINT_OK
    p = REPORTS_DIR / f"{scan_id}.json"
    if not p.exists():
        raise HTTPException(404, "Report not found")
    if not WEASYPRINT_OK:
        raise HTTPException(501, "PDF generation requires WeasyPrint: pip install weasyprint")
    report = json.loads(p.read_text(encoding="utf-8"))
    from fastapi.responses import Response
    pdf_bytes = generate_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="snitch-report-{scan_id}.pdf"'},
    )
