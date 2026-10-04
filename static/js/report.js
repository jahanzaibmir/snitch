/*
   Snitch */
const $ = (id) => document.getElementById(id);
const SCAN_ID = window.SCAN_ID;

const SEV_COLORS = {
  CRITICAL: '#96271F',
  HIGH:     '#A05B00',
  MEDIUM:   '#8A6D1B',
  LOW:      '#3E4C59',
};

let REPORT = null;
let CURRENT_FILTER = 'ALL';

document.addEventListener('DOMContentLoaded', init);

async function init() {
  // If the scan is still running when the page opens, show live progress.
  try {
    const res = await fetch('/api/status/' + SCAN_ID);
    if (res.ok) {
      const s = await res.json();
      if (s.status === 'queued' || s.status === 'running') return watchRunningScan(s);
      if (s.status === 'failed') return showFatal('Scan failed', s.error || 'The scan did not complete.');
    }
  } catch (_) { /* fall through — try loading the report directly */ }
  loadReport();
}



function watchRunningScan(first) {
  updateLoading(first);
  const timer = setInterval(async () => {
    try {
      const res = await fetch('/api/status/' + SCAN_ID);
      if (!res.ok) {
        clearInterval(timer);
        return showFatal('Scan not found', 'This scan no longer exists on the server.');
      }
      const s = await res.json();
      if (s.status === 'completed') { clearInterval(timer); loadReport(); }
      else if (s.status === 'failed') { clearInterval(timer); showFatal('Scan failed', s.error || ''); }
      else updateLoading(s);
    } catch (_) { /* keep watching */ }
  }, 1000);
}

function updateLoading(s) {
  $('loading-text').textContent = stageTitle(s.stage);
  $('loading-track').classList.remove('hidden');
  $('loading-fill').style.width = clampPct(s.progress) + '%';
  if (s.message) {
    $('loading-msg').textContent = s.message;
    $('loading-msg').classList.remove('hidden');
  }
}

function stageTitle(stage) {
  if (stage === 'clone') return 'Cloning repository…';
  if (stage === 'files') return 'Scanning files…';
  if (stage === 'git_history') return 'Scanning git history…';
  if (stage === 'done') return 'Finishing up…';
  return 'Loading report…';
}

function clampPct(p) {
  return Math.max(1, Math.min(99, Number(p) || 0));
}



async function loadReport() {
  try {
    const res = await fetch('/api/report/' + SCAN_ID);
    if (res.status === 404) {
      return showFatal('Report not available',
        'This report does not exist. If you just started the scan, give it a moment and refresh.');
    }
    if (!res.ok) {
      return showFatal('Could not load report', 'Server error ' + res.status + '. Refresh the page to retry.');
    }
    REPORT = await res.json();
    render();
  } catch (_) {
    showFatal('Connection problem',
      'Could not reach the Snitch server. Make sure it is still running, then refresh.');
  }
}

function showFatal(title, detail) {
  $('loading-state').classList.add('hidden');
  $('report-content').classList.add('hidden');
  $('error-state').classList.remove('hidden');
  $('error-title').textContent = title;
  $('error-detail').textContent = detail || '';
}

function render() {
  $('loading-state').classList.add('hidden');
  $('error-state').classList.add('hidden');
  $('report-content').classList.remove('hidden');
  $('report-id-badge').textContent = 'scan · ' + SCAN_ID;

  renderHeader();
  renderScoreboard();
  renderDonut();
  renderCategories();
  renderStats();
  renderTopFiles();
  renderFindings();
}

/*Header  */

function renderHeader() {
  const s = REPORT.summary || {};

  $('report-source').textContent = REPORT.source || 'Unknown source';
  $('report-source').title = REPORT.source || '';

  const st = REPORT.stats || {};
  const bits = [];
  if (REPORT.generated_at) bits.push(fmtDate(REPORT.generated_at));
  if (st.files_scanned != null) bits.push(st.files_scanned.toLocaleString() + ' files scanned');
  bits.push((s.total || 0) + ((s.total || 0) === 1 ? ' finding' : ' findings'));
  $('report-meta').innerHTML = bits
    .map((b) => `<span>${escapeHtml(b)}</span>`)
    .join('<span class="dot">·</span>');

  const risk = s.critical ? ['critical', 'Critical risk — act now']
    : s.high   ? ['high', 'High risk']
    : s.medium ? ['medium', 'Medium risk']
    : s.low    ? ['low', 'Low risk']
    :            ['clean', 'Clean — no secrets found'];
  $('report-risk').innerHTML =
    `<span class="risk-chip ${risk[0]}"><span class="risk-dot"></span>${risk[1]}</span>`;
}

function renderScoreboard() {
  const s = REPORT.summary || {};
  const cells = [
    ['critical', 'cnt-critical'],
    ['high', 'cnt-high'],
    ['medium', 'cnt-medium'],
    ['low', 'cnt-low'],
    ['total', 'cnt-total'],
  ];
  for (const [key, id] of cells) {
    const el = $(id);
    const v = s[key] || 0;
    el.textContent = v;
    const cell = el.closest('.score-cell');
    if (cell && key !== 'total') cell.classList.toggle('zero', v === 0);
  }
}

/* */
function renderDonut() {
  const canvas = $('donut-chart');
  if (!canvas) return;

  const s = REPORT.summary || {};
  const data = [
    { label: 'Critical', value: s.critical || 0, color: SEV_COLORS.CRITICAL },
    { label: 'High',     value: s.high || 0,     color: SEV_COLORS.HIGH },
    { label: 'Medium',   value: s.medium || 0,   color: SEV_COLORS.MEDIUM },
    { label: 'Low',      value: s.low || 0,      color: SEV_COLORS.LOW },
  ];
  const total = s.total || 0;

  const dpr = window.devicePixelRatio || 1;
  const size = 160;
  canvas.width = size * dpr;
  canvas.height = size * dpr;
  canvas.style.width = size + 'px';
  canvas.style.height = size + 'px';

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const cx = size / 2, cy = size / 2, r = 62, w = 15;

  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.strokeStyle = '#EDE9DD';
  ctx.lineWidth = w;
  ctx.stroke();

  let start = -Math.PI / 2;
  for (const d of data) {
    if (!d.value || !total) continue;
    const angle = (d.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r, start + 0.03, start + angle - 0.03);
    ctx.strokeStyle = d.color;
    ctx.lineWidth = w;
    ctx.lineCap = 'butt';
    ctx.stroke();
    start += angle;
  }

  ctx.fillStyle = '#111111';
  ctx.font = 'bold 32px Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(String(total), cx, cy - 7);
  ctx.fillStyle = '#666666';
  ctx.font = '11px Arial, sans-serif';
  ctx.fillText(total === 1 ? 'FINDING' : 'FINDINGS', cx, cy + 16);

  $('donut-legend').innerHTML = data.map((d) => `
    <div class="legend-item">
      <span class="legend-swatch" style="background:${d.color}"></span>
      ${d.label}<b>${d.value}</b>
    </div>`).join('');
}

/* Sidebar widgets  */

function renderCategories() {
  const cats = Object.entries(REPORT.categories || {}).sort((a, b) => b[1] - a[1]);
  if (!cats.length) {
    $('category-bars').innerHTML = '<p class="empty-note">No categories</p>';
    return;
  }
  const max = Math.max(...cats.map((c) => c[1]));
  $('category-bars').innerHTML = cats.map(([name, count]) => `
    <div class="cat-row">
      <div class="cat-top">
        <span class="cat-name">${escapeHtml(name)}</span>
        <span class="cat-count">${count}</span>
      </div>
      <div class="cat-track">
        <div class="cat-fill" style="width:${((count / max) * 100).toFixed(1)}%"></div>
      </div>
    </div>`).join('');
}

function renderStats() {
  const st = REPORT.stats || {};
  const tiles = [
    [st.files_scanned ?? 0, 'Files scanned'],
    [st.files_skipped ?? 0, 'Files skipped'],
    [REPORT.git_history_scanned ? 'Yes' : 'No', 'Git history'],
    [countUniqueFiles(), 'Files w/ findings'],
  ];
  $('stat-grid').innerHTML = tiles.map(([v, l]) => `
    <div class="stat-tile">
      <span class="st-val">${escapeHtml(String(v))}</span>
      <span class="st-lbl">${l}</span>
    </div>`).join('');
}

function countUniqueFiles() {
  return new Set((REPORT.findings || []).map((f) => f.file)).size;
}

function renderTopFiles() {
  const counts = {};
  for (const f of REPORT.findings || []) counts[f.file] = (counts[f.file] || 0) + 1;
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  $('top-files').innerHTML = top.length
    ? top.map(([file, n]) => `
        <div class="tf-row" title="${escapeHtml(file)}">
          <span class="tf-name">${escapeHtml(shortenPath(file, 34))}</span>
          <span class="tf-count">${n}</span>
        </div>`).join('')
    : '<p class="empty-note">No affected files</p>';
}

/*  Findings list F */

function renderFindings() {
  const findings = REPORT.findings || [];
  const s = REPORT.summary || {};
  const counts = {
    ALL: s.total || 0,
    CRITICAL: s.critical || 0,
    HIGH: s.high || 0,
    MEDIUM: s.medium || 0,
    LOW: s.low || 0,
  };

  document.querySelectorAll('.filter-btn').forEach((btn) => {
    const sev = btn.dataset.sev || 'ALL';
    const span = btn.querySelector('.filter-count');
    if (span) span.textContent = counts[sev] ?? '';
    btn.classList.toggle('zero-count', sev !== 'ALL' && !counts[sev]);
  });

  $('filter-bar').classList.toggle('hidden', counts.ALL === 0);

  if (!findings.length) {
    $('findings-list').innerHTML = '';
    $('no-findings').classList.remove('hidden');
    return;
  }

  $('no-findings').classList.add('hidden');
  $('findings-list').innerHTML = findings.map((f) => findingCard(f)).join('');
  applyFilters();
}

function findingCard(f) {
  const sev = (f.severity || 'LOW').toUpperCase();
  const ent = f.entropy || {};
  const haystack = `${f.file || ''} ${f.name || ''} ${f.category || ''} ${f.pattern_id || ''}`.toLowerCase();

  const chips = [];
  if (f.in_git_history) chips.push('<span class="chip chip-git">git history</span>');
  if (f.in_comment) chips.push('<span class="chip">in comment</span>');
  chips.push(`<span class="chip chip-entropy">H ${ent.score ?? '—'}</span>`);

  return `
  <div class="finding" data-sev="${sev.toLowerCase()}" data-search="${escapeHtml(haystack)}">
    <button class="finding-head" onclick="toggleFinding(this)" aria-expanded="false">
      <span class="sev-badge ${sev.toLowerCase()}">${sev}</span>
      <span class="finding-title">
        <span class="finding-name">${escapeHtml(f.name || f.pattern_id || 'Finding')}</span>
        <span class="finding-loc">${escapeHtml(f.file || '')}${f.line ? ':' + f.line : ''}</span>
      </span>
      <span class="finding-right">
        ${chips.join('')}
        <svg class="chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>
      </span>
    </button>
    <div class="finding-body hidden">${findingBody(f)}</div>
  </div>`;
}

function findingBody(f) {
  const ent = f.entropy || {};
  let html = `
    <div class="f-row">
      <span class="f-label">Matched value</span>
      <code class="f-value">${escapeHtml(f.redacted_value || '***')}</code>
    </div>`;

  if (f.line_content) {
    html += `
    <div class="f-row">
      <span class="f-label">Line ${f.line || ''}</span>
      <pre class="f-line">${escapeHtml(trimLine(f.line_content))}</pre>
    </div>`;
  }

  html += `
    <div class="f-row">
      <span class="f-label">Entropy</span>
      <span class="f-ent">
        <b>${ent.score ?? '—'}</b>
        <span class="ent-label ent-${ent.label || 'na'}">${escapeHtml(ent.label || 'n/a')}</span>
        ${ent.is_likely_real
          ? '<span class="ent-real">likely a real secret</span>'
          : '<span class="ent-fp">likely a placeholder</span>'}
      </span>
    </div>`;

  if (f.in_git_history && f.commit_hash) {
    html += `
    <div class="f-commit">
      <span class="f-label">Found in git history</span>
      <code>${escapeHtml(f.commit_hash)}</code>
      ${f.commit_message ? `<span class="commit-msg">“${escapeHtml(f.commit_message)}”</span>` : ''}
      ${f.commit_author ? `<span class="commit-meta">${escapeHtml(f.commit_author)}${f.commit_date ? ' · ' + escapeHtml(fmtDate(f.commit_date)) : ''}</span>` : ''}
    </div>`;
  }

  if (f.remediation) {
    html += `
    <div class="f-remedy">
      <span class="f-label">How to fix</span>
      <p>${escapeHtml(f.remediation)}</p>
    </div>`;
  }

  return html;
}

/*  Filtering  */

window.setFilter = function (sev, btn) {
  CURRENT_FILTER = sev;
  document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
};

window.applyFilters = function () {
  const term = ($('search-input').value || '').trim().toLowerCase();
  let visible = 0;

  document.querySelectorAll('.finding').forEach((el) => {
    const okSev = CURRENT_FILTER === 'ALL' || el.dataset.sev === CURRENT_FILTER.toLowerCase();
    const okSearch = !term || (el.dataset.search || '').includes(term);
    const show = okSev && okSearch;
    el.classList.toggle('hidden', !show);
    if (show) visible++;
  });

  const hasFindings = document.querySelectorAll('.finding').length > 0;
  $('no-matches').classList.toggle('hidden', !(hasFindings && visible === 0));
};

window.toggleFinding = function (btn) {
  const card = btn.closest('.finding');
  const body = btn.nextElementSibling;
  if (!card || !body) return;
  const willOpen = body.classList.contains('hidden');
  body.classList.toggle('hidden', !willOpen);
  card.classList.toggle('open', willOpen);
  btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
};

/* Helpers  */

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function trimLine(s) {
  s = String(s).trim();
  return s.length > 400 ? s.slice(0, 400) + '…' : s;
}

function shortenPath(p, max) {
  p = String(p);
  if (p.length <= max) return p;
  return p.slice(0, Math.ceil(max / 2) - 1) + '…' + p.slice(-Math.floor(max / 2));
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}