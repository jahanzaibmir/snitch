# Snitch 🔍

Secret & credential leak scanner for Git repositories and codebases.

---

## Quick Start (Windows)

### Prerequisites
- Python 3.10 or higher — [python.org](https://www.python.org/downloads/)
  - During install, check **"Add Python to PATH"**
- Git — [git-scm.com](https://git-scm.com/download/win)

### Setup
```
Double-click:  scripts\setup.bat
```

### Run
```
Double-click:  scripts\start.bat
```

Opens automatically at **http://localhost:8000**

### Test engine
```
Double-click:  scripts\test.bat
```

---

## What it detects

| Category       | Examples                              |
|----------------|---------------------------------------|
| Cloud          | AWS keys, GCP service accounts, Azure |
| Source Control | GitHub PAT, GitLab tokens             |
| Payment        | Stripe, PayPal, Braintree             |
| Communication  | Twilio, SendGrid, Mailgun, Slack      |
| Auth           | JWT tokens, OAuth client secrets      |
| Database       | PostgreSQL, MySQL, MongoDB URLs       |
| Cryptography   | RSA, EC, SSH, PGP private keys        |
| AI Services    | OpenAI, Anthropic, HuggingFace        |

---

## Project Structure

```
snitch/
├── engine/
│   ├── __init__.py       # Public API
│   ├── patterns.py       # 30+ regex patterns
│   ├── entropy.py        # Shannon entropy analysis
│   ├── scanner.py        # File/directory scanner
│   └── git_scanner.py    # Git history scanner
├── api/
│   ├── __init__.py
│   └── main.py           # FastAPI backend
├── static/
│   ├── css/
│   │   ├── main.css      # Design system
│   │   └── report.css    # Report page styles
│   └── js/
│       ├── main.js       # Landing page logic
│       └── report.js     # Report page logic
├── templates/
│   ├── index.html        # Landing page
│   └── report.html       # Report page
├── uploads/              # Temp upload storage (auto-created)
├── reports/              # Scan results JSON (auto-created)
├── scripts/
│   ├── setup.bat         # Windows setup
│   ├── start.bat         # Windows start
│   └── test.bat          # Run engine tests
├── test_engine.py        # Engine smoke tests
└── requirements.txt
```

---

## Severity Levels

| Level    | Meaning                                         |
|----------|-------------------------------------------------|
| CRITICAL | Immediate risk — rotate/revoke now              |
| HIGH     | Significant exposure — rotate soon              |
| MEDIUM   | Possible secret — review and rotate if real     |
| LOW      | Low-confidence match — manual review needed     |

---

## How it works

1. **Pattern matching** — 30+ regex patterns targeting known secret formats
2. **Entropy analysis** — Shannon entropy filters out placeholder/test values
3. **False positive reduction** — skips `node_modules`, example files, binary files, test fixtures
4. **Git history scan** — walks commit diffs to catch secrets removed from current files
5. **Severity scoring** — entropy + pattern type + context (commented, git history) determines final severity

---

## API Endpoints

| Method | Path                             | Description              |
|--------|----------------------------------|--------------------------|
| POST   | /api/scan/url                    | Start scan from URL      |
| POST   | /api/scan/upload                 | Start scan from ZIP      |
| GET    | /api/status/{scan_id}            | Poll scan progress       |
| GET    | /api/report/{scan_id}            | Fetch report JSON        |
| GET    | /api/report/{scan_id}/download/json | Download report       |
| GET    | /api/health                      | Health check             |
