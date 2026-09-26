'use strict';

// Tab switching
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  document.getElementById('panel-' + tab).classList.add('active');
  clearError();
}

// File handling
let selectedFile = null;

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.add('drag-over');
}
function handleDragLeave() {
  document.getElementById('drop-zone').classList.remove('drag-over');
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) applyFile(f);
}
function handleFileSelect(e) {
  const f = e.target.files[0];
  if (f) applyFile(f);
}

// Accept any file — zip, folder zip, txt, c, py, js, etc.
// Backend handles zip extraction; other files get wrapped into a zip on the fly
function applyFile(f) {
  if (!f) return;
  selectedFile = f;
  const el = document.getElementById('file-selected');
  el.textContent = '\u2713  ' + f.name + '  (' + fmtBytes(f.size) + ')';
  el.classList.remove('hidden');
  document.getElementById('upload-btn').removeAttribute('disabled');
  clearError();
}

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

// Scan via URL
async function startUrlScan() {
  const url = document.getElementById('repo-url').value.trim();
  if (!url) { showError('Please enter a repository URL.'); return; }
  if (!url.startsWith('https://github.com') && !url.startsWith('https://gitlab.com')) {
    showError('Only GitHub and GitLab URLs are supported.'); return;
  }
  clearError();
  showOverlay('Starting scan...');
  try {
    const fd = new FormData();
    fd.append('url', url);
    const r = await fetch('/api/scan/url', { method: 'POST', body: fd });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Request failed');
    poll(d.scan_id);
  } catch(e) { hideOverlay(); showError(e.message); }
}

// Scan via upload — wraps non-zip files into a zip before sending
async function startUploadScan() {
  if (!selectedFile) { showError('Please pick a file first.'); return; }
  clearError();
  showOverlay('Uploading...');
  try {
    const fd = new FormData();
    // If it's already a zip, send as-is. Otherwise wrap it.
    if (selectedFile.name.endsWith('.zip')) {
      fd.append('file', selectedFile, selectedFile.name);
    } else {
      const zip = await wrapInZip(selectedFile);
      fd.append('file', zip, 'upload.zip');
    }
    const r = await fetch('/api/scan/upload', { method: 'POST', body: fd });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Upload failed');
    poll(d.scan_id);
  } catch(e) { hideOverlay(); showError(e.message); }
}

// Wrap a single file into a zip using the browser's CompressionStream
// Falls back to sending as a plain zip with the file contents
async function wrapInZip(file) {
  // Build a minimal ZIP file in memory
  const content = await file.arrayBuffer();
  const bytes = new Uint8Array(content);
  const name = file.name;
  const nameBytes = new TextEncoder().encode(name);

  // Local file header
  const header = new Uint8Array([
    0x50,0x4B,0x03,0x04, // signature
    0x14,0x00,           // version needed
    0x00,0x00,           // flags
    0x00,0x00,           // compression (stored)
    0x00,0x00,           // mod time
    0x00,0x00,           // mod date
    0x00,0x00,0x00,0x00, // crc32 (0 = skip check)
    ...intToBytes(bytes.length, 4), // compressed size
    ...intToBytes(bytes.length, 4), // uncompressed size
    ...intToBytes(nameBytes.length, 2), // filename length
    0x00,0x00,           // extra field length
    ...nameBytes,
    ...bytes,
  ]);

  // Central directory
  const central = new Uint8Array([
    0x50,0x4B,0x01,0x02,
    0x14,0x00,0x14,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    ...intToBytes(bytes.length, 4),
    ...intToBytes(bytes.length, 4),
    ...intToBytes(nameBytes.length, 2),
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    ...nameBytes,
  ]);

  const centralOffset = header.length;
  const centralSize   = central.length;

  // End of central directory
  const eocd = new Uint8Array([
    0x50,0x4B,0x05,0x06,
    0x00,0x00,0x00,0x00,
    0x01,0x00,0x01,0x00,
    ...intToBytes(centralSize, 4),
    ...intToBytes(centralOffset, 4),
    0x00,0x00,
  ]);

  const blob = new Blob([header, central, eocd], { type: 'application/zip' });
  return blob;
}

function intToBytes(n, len) {
  const arr = [];
  for (let i = 0; i < len; i++) { arr.push(n & 0xff); n >>= 8; }
  return arr;
}

// Polling
async function poll(id) {
  try {
    const r = await fetch('/api/status/' + id);
    if (!r.ok) { setTimeout(() => poll(id), 1500); return; }
    const d = await r.json();
    updateOverlay(d.stage || '...', d.progress || 0);
    if (d.status === 'done') { window.location.href = '/report/' + id; return; }
    if (d.status === 'error') { hideOverlay(); showError('Scan failed: ' + (d.error || 'Unknown error')); return; }
    setTimeout(() => poll(id), 1000);
  } catch { setTimeout(() => poll(id), 2000); }
}

// Overlay
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
function hideOverlay() { document.getElementById('scan-overlay').classList.add('hidden'); }

// Error
function showError(msg) {
  const el = document.getElementById('scan-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}
function clearError() { document.getElementById('scan-error').classList.add('hidden'); }

// Enter key on URL input
document.getElementById('repo-url').addEventListener('keydown', e => {
  if (e.key === 'Enter') startUrlScan();
});
