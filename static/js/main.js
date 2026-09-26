/* Snitch — main.js */

'use strict';

// ── Tab switching ──────────────────────────────────────────────────────────────

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.getElementById('panel-' + tab).classList.add('active');
  clearError();
}

// ── Drop zone ──────────────────────────────────────────────────────────────────

let selectedFile = null;

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.add('drag-over');
}

function handleDragLeave(e) {
  document.getElementById('drop-zone').classList.remove('drag-over');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) applyFile(file);
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) applyFile(file);
}

function applyFile(file) {
  if (!file.name.endsWith('.zip')) {
    showError('Only .zip files are supported.');
    return;
  }
  selectedFile = file;
  const el = document.getElementById('file-selected');
  el.textContent = `✓  ${file.name}  (${formatBytes(file.size)})`;
  el.classList.remove('hidden');
  document.getElementById('upload-btn').removeAttribute('disabled');
  clearError();
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ── Scan: URL ──────────────────────────────────────────────────────────────────

async function startUrlScan() {
  const url = document.getElementById('repo-url').value.trim();
  if (!url) { showError('Please enter a repository URL.'); return; }
  if (!url.startsWith('https://github.com') && !url.startsWith('https://gitlab.com')) {
    showError('Only GitHub and GitLab URLs are supported.');
    return;
  }

  clearError();
  showOverlay('Queuing scan...');

  try {
    const form = new FormData();
    form.append('url', url);

    const res = await fetch('/api/scan/url', { method: 'POST', body: form });
    const data = await res.json();

    if (!res.ok) throw new Error(data.detail || 'Scan request failed');

    pollStatus(data.scan_id);
  } catch (err) {
    hideOverlay();
    showError(err.message);
  }
}

// ── Scan: Upload ───────────────────────────────────────────────────────────────

async function startUploadScan() {
  if (!selectedFile) { showError('Please select a ZIP file first.'); return; }

  clearError();
  showOverlay('Uploading archive...');

  try {
    const form = new FormData();
    form.append('file', selectedFile);

    const res = await fetch('/api/scan/upload', { method: 'POST', body: form });
    const data = await res.json();

    if (!res.ok) throw new Error(data.detail || 'Upload failed');

    pollStatus(data.scan_id);
  } catch (err) {
    hideOverlay();
    showError(err.message);
  }
}

// ── Polling ────────────────────────────────────────────────────────────────────

async function pollStatus(scanId) {
  const poll = async () => {
    try {
      const res = await fetch('/api/status/' + scanId);
      const data = await res.json();

      updateOverlay(data.stage || '...', data.progress || 0);

      if (data.status === 'done') {
        window.location.href = '/report/' + scanId;
        return;
      }

      if (data.status === 'error') {
        hideOverlay();
        showError('Scan failed: ' + (data.error || 'Unknown error'));
        return;
      }

      setTimeout(poll, 1200);
    } catch (err) {
      setTimeout(poll, 2000);
    }
  };

  poll();
}

// ── Overlay ────────────────────────────────────────────────────────────────────

function showOverlay(stage) {
  document.getElementById('scan-overlay').classList.remove('hidden');
  document.getElementById('overlay-stage').textContent = stage;
  document.getElementById('progress-fill').style.width = '0%';
  document.getElementById('overlay-pct').textContent = '0%';
}

function updateOverlay(stage, pct) {
  document.getElementById('overlay-stage').textContent = stage;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('overlay-pct').textContent = pct + '%';
}

function hideOverlay() {
  document.getElementById('scan-overlay').classList.add('hidden');
}

// ── Error ──────────────────────────────────────────────────────────────────────

function showError(msg) {
  const el = document.getElementById('scan-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function clearError() {
  document.getElementById('scan-error').classList.add('hidden');
}

// ── Enter key on URL input ─────────────────────────────────────────────────────

document.getElementById('repo-url').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startUrlScan();
});
