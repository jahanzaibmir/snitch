/* ═══════════════════════════════════════════════════════════
   Snitch — landing page
   Scan start, upload handling, live progress — plus recent
   scan history stored in localStorage.
   ═══════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);
const MAX_UPLOAD_MB = 50;
const POLL_INTERVAL_MS = 900;
const POLL_TIMEOUT_MS = 15 * 60 * 1000;
const RECENT_KEY = 'snitch_recent_scans';
const RECENT_LIMIT = 6;

let pollTimer = null;
let selectedFile = null;
let scanning = false;

document.addEventListener('DOMContentLoaded', renderRecent);

/* ── Tabs ─────────────────────────────────────────────── */

function switchTab(tab) {
  const isUrl = tab === 'url';
  $('tab-url').classList.toggle('active', isUrl);
  $('tab-upload').classList.toggle('active', !isUrl);
  $('panel-url').classList.toggle('active', isUrl);
  $('panel-upload').classList.toggle('active', !isUrl);
  hideError();
}

/* ── Inline errors ────────────────────────────────────── */

function showError(msg) {
  const box = $('scan-error');
  box.textContent = msg;
  box.classList.remove('hidden');
}
function hideError() {
  $('scan-error').classList.add('hidden');
}

/* ── Repo URL scan ────────────────────────────────────── */

async function startUrlScan() {
  if (scanning) return;
  hideError();

  const url = $('repo-url').value.trim();
  if (!url) return showError('Enter a repository URL first.');
  if (!/^(https?:\/\/|git@)/i.test(url)) {
    return showError('URL must start with https:// (or git@ for SSH).');
  }

  scanning = true;
  showOverlay('Starting scan…', 1);
  try {
    const res = await fetch('/api/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Could not start the scan.');
    rememberScan(data.scan_id, url);
    pollScan(data.scan_id);
  } catch (err) {
    scanning = false;
    hideOverlay();
    showError(err.message || 'Something went wrong.');
  }
}

/* ── File upload ──────────────────────────────────────── */

function handleFileSelect(e) {
  setSelectedFile(e.target.files && e.target.files[0]);
}
function handleDragOver(e) {
  e.preventDefault();
  $('drop-zone').classList.add('drag');
}
function handleDragLeave() {
  $('drop-zone').classList.remove('drag');
}
function handleDrop(e) {
  e.preventDefault();
  $('drop-zone').classList.remove('drag');
  setSelectedFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
}

function setSelectedFile(file) {
  hideError();
  selectedFile = file || null;
  const chip = $('file-selected');
  const btn = $('upload-btn');

  if (!selectedFile) {
    chip.classList.add('hidden');
    chip.innerHTML = '';
    btn.disabled = true;
    return;
  }
  if (selectedFile.size > MAX_UPLOAD_MB * 1024 * 1024) {
    selectedFile = null;
    chip.classList.add('hidden');
    chip.innerHTML = '';
    btn.disabled = true;
    return showError('File is too large — the limit is ' + MAX_UPLOAD_MB + ' MB.');
  }

  const kb = selectedFile.size / 1024;
  const size = kb >= 1024 ? (kb / 1024).toFixed(1) + ' MB' : Math.round(kb) + ' KB';
  chip.innerHTML =
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>' +
    '<div class="fs-info"><div class="fs-name">' + escapeHtml(selectedFile.name) + '</div>' +
    '<div class="fs-size">' + size + '</div></div>' +
    '<button class="fs-remove" onclick="clearSelectedFile()" title="Remove file" aria-label="Remove file">✕</button>';
  chip.classList.remove('hidden');
  btn.disabled = false;
}

function clearSelectedFile() {
  setSelectedFile(null);
  $('file-input').value = '';
}

function startUploadScan() {
  if (scanning || !selectedFile) return;
  hideError();
  scanning = true;

  const fd = new FormData();
  fd.append('file', selectedFile);

  showOverlay('Uploading file…', 2);

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/scan/upload');
  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      updateOverlay('Uploading file…', Math.max(2, Math.round((e.loaded / e.total) * 7)));
    }
  };
  xhr.onload = () => {
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
    if (xhr.status >= 200 && xhr.status < 300) {
      rememberScan(data.scan_id, selectedFile.name);
      pollScan(data.scan_id);
    } else {
      scanning = false;
      hideOverlay();
      showError(data.detail || 'Upload failed.');
    }
  };
  xhr.onerror = () => {
    scanning = false;
    hideOverlay();
    showError('Network error while uploading.');
  };
  xhr.send(fd);
}

/* ── Polling ──────────────────────────────────────────── */

function pollScan(scanId) {
  const startedAt = Date.now();
  updateOverlay('Scanning…', 8);

  pollTimer = setInterval(async () => {
    if (Date.now() - startedAt > POLL_TIMEOUT_MS) {
      stopPoll();
      scanning = false;
      hideOverlay();
      showError('Scan timed out. Try a smaller repository, or upload a ZIP of it.');
      return;
    }
    try {
      const res = await fetch('/api/status/' + scanId);
      if (res.status === 404) {
        stopPoll(); scanning = false; hideOverlay();
        showError('Scan not found. Please try again.');
        return;
      }
      const s = await res.json();
      if (s.status === 'completed') {
        stopPoll();
        updateOverlay('Scan complete — building report…', 100);
        setTimeout(() => { window.location.href = '/report/' + scanId; }, 500);
      } else if (s.status === 'failed') {
        stopPoll(); scanning = false; hideOverlay();
        showError(s.error || 'Scan failed.');
      } else {
        updateOverlay(stageTitle(s.stage), clampPct(s.progress));
        setOverlayMsg(s.message);
      }
    } catch (_) { /* transient network hiccup — keep polling */ }
  }, POLL_INTERVAL_MS);
}

function stopPoll() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function stageTitle(stage) {
  if (stage === 'clone') return 'Cloning repository…';
  if (stage === 'files') return 'Scanning files…';
  if (stage === 'git_history') return 'Scanning git history…';
  return 'Scanning…';
}
function clampPct(p) {
  return Math.max(1, Math.min(99, Number(p) || 0));
}

/* ── Recent scans (localStorage) ──────────────────────── */

function loadRecent() {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY));
    return Array.isArray(raw) ? raw : [];
  } catch (_) {
    return [];
  }
}

function rememberScan(id, label) {
  if (!id) return;
  let recent = loadRecent().filter((x) => x.id !== id);
  recent.unshift({ id: id, label: String(label || id), at: Date.now() });
  recent = recent.slice(0, RECENT_LIMIT);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(recent));
  } catch (_) { /* storage full or blocked — non-fatal */ }
  renderRecent();
}

function renderRecent() {
  const wrap = $('recent-scans');
  const list = $('recent-list');
  if (!wrap || !list) return;

  const recent = loadRecent();
  if (!recent.length) {
    wrap.classList.add('hidden');
    list.innerHTML = '';
    return;
  }

  wrap.classList.remove('hidden');
  list.innerHTML = recent.map((x) =>
    `<button class="recent-chip" onclick="openRecent('${x.id}')" title="${escapeHtml(x.label)}">` +
      `<span class="rc-label">${escapeHtml(x.label)}</span>` +
      `<span class="rc-date">${escapeHtml(fmtRecent(x.at))}</span>` +
    `</button>`
  ).join('');
}

function openRecent(id) {
  if (id && /^[a-f0-9]{12}$/.test(id)) {
    window.location.href = '/report/' + id;
  }
}

function clearRecentScans() {
  try { localStorage.removeItem(RECENT_KEY); } catch (_) { /* ignore */ }
  renderRecent();
}

function fmtRecent(t) {
  const d = new Date(t);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/* ── Overlay ──────────────────────────────────────────── */

function showOverlay(title, pct) {
  $('scan-overlay').classList.remove('hidden');
  setOverlayMsg('');
  updateOverlay(title, pct);
}
function hideOverlay() {
  $('scan-overlay').classList.add('hidden');
}
function updateOverlay(title, pct) {
  $('overlay-stage').textContent = title;
  $('progress-fill').style.width = (pct || 0) + '%';
  $('overlay-pct').textContent = Math.round(pct || 0) + '%';
}
function setOverlayMsg(msg) {
  const el = $('overlay-msg');
  el.textContent = msg || '';
  el.classList.toggle('hidden', !msg);
}

/* ── Helpers ──────────────────────────────────────────── */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

 $('repo-url').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startUrlScan();
});