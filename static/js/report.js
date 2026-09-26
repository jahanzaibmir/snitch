/* Snitch — report.js */

'use strict';

let reportData = null;
let activeFilter = 'ALL';

// ── Boot ───────────────────────────────────────────────────────────────────────

async function loadReport() {
  try {
    const res = await fetch('/api/report/' + SCAN_ID);
    if (!res.ok) throw new Error('Report not found');
    reportData = await res.json();
    renderReport();
  } catch (err) {
    document.getElementById('loading-state').innerHTML =
      `<p style="color:var(--text-muted)">Failed to load report: ${err.message}</p>`;
  }
}

function renderReport() {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('report-content').classList.remove('hidden');

  // Report ID badge
  document.getElementById('report-id-badge').textContent = 'Scan #' + SCAN_ID;

  // Source
  document.getElementById('summary-source').textContent = reportData.source || '';

  // Summary counts
  const s = reportData.summary || {};
  setCount('count-critical', s.critical || 0);
  setCount('count-high', s.high || 0);
  setCount('count-medium', s.medium || 0);
  setCount('count-low', s.low || 0);
  setCount('count-total', s.total || 0);

  // Stats
  const stats = reportData.stats || {};
  document.getElementById('stat-files-scanned').textContent = (stats.files_scanned ?? '—').toLocaleString();
  document.getElementById('stat-files-skipped').textContent = (stats.files_skipped ?? '—').toLocaleString();

  const dt = reportData.generated_at
    ? new Date(reportData.generated_at).toLocaleString()
    : '—';
  document.getElementById('stat-generated').textContent = dt;

  // Findings
  renderFindings();
}

function setCount(id, val) {
  document.getElementById(id).querySelector('.count-num').textContent = val;
}

// ── Findings ───────────────────────────────────────────────────────────────────

function renderFindings() {
  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  const searchVal = (document.getElementById('search-input').value || '').toLowerCase();
  const findings = reportData.findings || [];

  const filtered = findings.filter(f => {
    if (activeFilter !== 'ALL' && f.severity !== activeFilter) return false;
    if (searchVal) {
      const haystack = (f.name + f.file + f.category + f.pattern_id).toLowerCase();
      if (!haystack.includes(searchVal)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    document.getElementById('no-findings').classList.remove('hidden');
    return;
  }

  document.getElementById('no-findings').classList.add('hidden');

  filtered.forEach(f => {
    list.appendChild(buildFindingCard(f));
  });
}

function buildFindingCard(f) {
  const card = document.createElement('div');
  card.className = `finding-card sev-${f.severity}`;

  const locationText = f.in_git_history
    ? `git:${f.commit_hash}  line ${f.line}`
    : `${f.file}  :${f.line}`;

  card.innerHTML = `
    <div class="finding-header" onclick="toggleCard(this)">
      <span class="sev-badge badge-${f.severity}">${f.severity}</span>
      <span class="finding-name">${escHtml(f.name)}</span>
      ${f.in_git_history ? '<span class="git-badge">git history</span>' : ''}
      <span class="finding-location">${escHtml(locationText)}</span>
      <svg class="finding-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="finding-body">
      <div class="finding-section-label">Matched value (redacted)</div>
      <div class="finding-value">${escHtml(f.redacted_value || '—')}</div>

      <div class="finding-section-label">Source line</div>
      <div class="finding-code">${escHtml((f.line_content || '').trim())}</div>

      <div class="finding-section-label">Entropy</div>
      <div class="finding-meta">
        <div class="meta-item">
          <span class="meta-key">Score</span>
          <span class="meta-val entropy-${f.entropy?.label || 'low'}">${f.entropy?.score ?? '—'}</span>
        </div>
        <div class="meta-item">
          <span class="meta-key">Level</span>
          <span class="meta-val entropy-${f.entropy?.label || 'low'}">${f.entropy?.label ?? '—'}</span>
        </div>
        <div class="meta-item">
          <span class="meta-key">Category</span>
          <span class="meta-val">${escHtml(f.category || '—')}</span>
        </div>
        ${f.in_comment ? `<div class="meta-item"><span class="meta-key">Note</span><span class="meta-val" style="color:var(--text-dim)">Found in comment</span></div>` : ''}
      </div>

      ${f.in_git_history && f.commit_hash ? `
        <div class="finding-section-label">Git commit</div>
        <div class="finding-meta">
          <div class="meta-item">
            <span class="meta-key">Hash</span>
            <span class="meta-val">${escHtml(f.commit_hash)}</span>
          </div>
          <div class="meta-item">
            <span class="meta-key">Message</span>
            <span class="meta-val" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(f.commit_message || '')}</span>
          </div>
        </div>
      ` : ''}

      <div class="finding-section-label">Remediation</div>
      <div class="finding-remediation">${escHtml(f.remediation || '—')}</div>
    </div>
  `;

  return card;
}

function toggleCard(header) {
  header.parentElement.classList.toggle('expanded');
}

// ── Filters ────────────────────────────────────────────────────────────────────

function setFilter(filter, btn) {
  activeFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings();
}

function applyFilters() {
  renderFindings();
}

// ── Export ─────────────────────────────────────────────────────────────────────

function downloadJSON() {
  window.open('/api/report/' + SCAN_ID + '/download/json', '_blank');
}

// ── Utilities ──────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ───────────────────────────────────────────────────────────────────────

loadReport();
