'use strict';

/* ─────────────────────────────────────────────────────────────────────────
   report.js  —  Snitch report dashboard
   Depends on:  SCAN_ID  (injected by report.html before this script loads)
                downloadJSON()  (also injected by report.html)
   ───────────────────────────────────────────────────────────────────────── */

let R            = null;   // full report JSON
let activeFilter = 'ALL';

const SEV_COLORS = {
  CRITICAL : '#ef4444',
  HIGH     : '#f06025',
  MEDIUM   : '#f59e0b',
  LOW      : '#60a5fa',
};
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/* ── helpers ────────────────────────────────────────────────────────────── */
function $(id)   { return document.getElementById(id); }
function esc(s)  {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

/* ── boot ───────────────────────────────────────────────────────────────── */
async function loadReport() {
  try {
    const res = await fetch('/api/report/' + SCAN_ID);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    R = await res.json();
    render();
  } catch (err) {
    const el = $('loading-state');
    if (el) el.innerHTML =
      `<p style="color:var(--red);padding:0 24px">
         Failed to load report — ${esc(err.message)}.<br>
         <a href="/" style="color:var(--orange)">← Back to scanner</a>
       </p>`;
  }
}

/* ── top-level render ───────────────────────────────────────────────────── */
function render() {
  $('loading-state').classList.add('hidden');
  $('report-content').classList.remove('hidden');

  /* nav badge */
  setText('report-id-badge', 'Scan #' + SCAN_ID);

  /* header */
  setText('report-source', R.source || '');
  setText('report-meta',   R.generated_at
    ? 'Scanned ' + new Date(R.generated_at).toLocaleString()
    : '');

  /* scoreboard */
  const s = R.summary || {};
  setText('cnt-critical', s.critical || 0);
  setText('cnt-high',     s.high     || 0);
  setText('cnt-medium',   s.medium   || 0);
  setText('cnt-low',      s.low      || 0);
  setText('cnt-total',    s.total    || 0);

  renderDonut();
  renderCategoryBars();
  renderStatGrid();
  renderTopFiles();
  renderFindings();
}

/* ── donut chart ────────────────────────────────────────────────────────── */
function renderDonut() {
  const s     = R.summary || {};
  const total = s.total   || 0;
  const data  = SEV_ORDER
    .map(k => ({ label: k, val: s[k.toLowerCase()] || 0, color: SEV_COLORS[k] }))
    .filter(d => d.val > 0);

  const canvas = $('donut-chart');
  if (!canvas) return;
  const ctx  = canvas.getContext('2d');
  const cx = 80, cy = 80, outerR = 62, holeR = 42;

  ctx.clearRect(0, 0, 160, 160);

  /* resolve CSS variables so the hole matches the actual page background */
  const style     = getComputedStyle(document.documentElement);
  const bgColor   = style.getPropertyValue('--bg').trim()         || '#f5f5f5';
  const textColor = style.getPropertyValue('--text').trim()       || '#111111';
  const dimColor  = style.getPropertyValue('--text-dim').trim()   || '#999999';
  const borderClr = style.getPropertyValue('--border').trim()     || '#e4e4e4';

  if (data.length === 0) {
    /* empty ring */
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.strokeStyle = borderClr;
    ctx.lineWidth   = outerR - holeR;
    ctx.stroke();
    /* "0 findings" label */
    ctx.fillStyle    = dimColor;
    ctx.font         = '11px "Space Grotesk", sans-serif';
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('0 findings', cx, cy);
  } else {
    /* segments */
    let angle = -Math.PI / 2;
    data.forEach(d => {
      const sweep = (d.val / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, outerR, angle, angle + sweep);
      ctx.closePath();
      ctx.fillStyle = d.color;
      ctx.fill();
      angle += sweep;
    });
    /* donut hole — must match actual bg, not hardcoded white */
    ctx.beginPath();
    ctx.arc(cx, cy, holeR, 0, Math.PI * 2);
    ctx.fillStyle = bgColor;
    ctx.fill();
    /* centre labels */
    ctx.fillStyle    = textColor;
    ctx.font         = 'bold 20px "Space Grotesk", sans-serif';
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 7);
    ctx.fillStyle = dimColor;
    ctx.font      = '11px "Space Grotesk", sans-serif';
    ctx.fillText('findings', cx, cy + 11);
  }

  /* legend */
  const leg = $('donut-legend');
  if (!leg) return;
  leg.innerHTML = '';
  if (data.length === 0) {
    leg.innerHTML = '<p style="font-size:.78rem;color:var(--text-dim);text-align:center">No findings</p>';
    return;
  }
  data.forEach(d => {
    const pct = Math.round(d.val / total * 100);
    leg.insertAdjacentHTML('beforeend', `
      <div class="legend-row">
        <span class="legend-label">
          <span class="legend-dot" style="background:${d.color}"></span>${esc(d.label)}
        </span>
        <span class="legend-val">${d.val}<span class="legend-pct"> ${pct}%</span></span>
      </div>`);
  });
}

/* ── category bars ──────────────────────────────────────────────────────── */
function renderCategoryBars() {
  const cats = R.categories || {};
  const el   = $('category-bars');
  if (!el) return;
  const entries = Object.entries(cats).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    el.innerHTML = '<p style="font-size:.78rem;color:var(--text-dim)">No findings</p>';
    return;
  }
  const max = entries[0][1] || 1;
  el.innerHTML = entries.map(([cat, count]) => {
    const pct = Math.round(count / max * 100);
    return `<div class="cat-bar-row">
      <div class="cat-bar-label"><span>${esc(cat)}</span><span>${count}</span></div>
      <div class="cat-bar-track"><div class="cat-bar-fill" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');
}

/* ── stat grid ──────────────────────────────────────────────────────────── */
function renderStatGrid() {
  const st = R.stats || {};
  const el = $('stat-grid');
  if (!el) return;
  const dur = st.duration_seconds != null
    ? st.duration_seconds.toFixed(1) + 's'
    : '—';
  const fmtNum = v => (v != null ? Number(v).toLocaleString() : '—');
  const cells = [
    ['Files scanned', fmtNum(st.files_scanned)],
    ['Files skipped', fmtNum(st.files_skipped)],
    ['Patterns run',  '30+'],
    ['Scan time',     dur],
  ];
  el.innerHTML = cells.map(([k, v]) => `
    <div class="stat-cell">
      <span class="stat-cell-val">${esc(v)}</span>
      <span class="stat-cell-key">${esc(k)}</span>
    </div>`).join('');
}

/* ── top affected files ─────────────────────────────────────────────────── */
function renderTopFiles() {
  const el = $('top-files');
  if (!el) return;
  const findings = R.findings || [];
  const freq = {};
  findings.forEach(f => {
    const key = f.file || '(unknown)';
    freq[key] = (freq[key] || 0) + 1;
  });
  const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!sorted.length) {
    el.innerHTML = '<p style="font-size:.78rem;color:var(--text-dim)">No findings</p>';
    return;
  }
  el.innerHTML = sorted.map(([file, count]) => {
    const short = file.split(/[/\\]/).pop() || file;
    return `<div class="top-file-row">
      <span class="top-file-name" title="${esc(file)}">${esc(short)}</span>
      <span class="top-file-badge">${count}</span>
    </div>`;
  }).join('');
}

/* ── findings list ──────────────────────────────────────────────────────── */
function renderFindings() {
  const searchEl = $('search-input');
  const query    = searchEl ? searchEl.value.toLowerCase() : '';
  const all      = R.findings || [];

  const filtered = all.filter(f => {
    if (activeFilter !== 'ALL' && f.severity !== activeFilter) return false;
    if (query) {
      const hay = [f.name, f.file, f.category, f.pattern_id]
        .map(v => (v || '').toLowerCase())
        .join(' ');
      if (!hay.includes(query)) return false;
    }
    return true;
  });

  const countEl = $('filter-count');
  if (countEl) countEl.textContent = filtered.length + ' of ' + all.length;

  const noF  = $('no-findings');
  const list = $('findings-list');
  if (!list) return;

  if (filtered.length === 0) {
    list.innerHTML = '';
    if (noF) noF.classList.remove('hidden');
    return;
  }
  if (noF) noF.classList.add('hidden');

  const wrap = document.createElement('div');
  wrap.className = 'findings-stack';
  filtered.forEach(f => wrap.appendChild(buildCard(f)));
  list.innerHTML = '';
  list.appendChild(wrap);
}

/* alias for the search input's oninput handler */
function applyFilters() { renderFindings(); }

/* ── individual finding card ────────────────────────────────────────────── */
function buildCard(f) {
  const card = document.createElement('div');
  card.className = `finding-card sev-${esc(f.severity || 'LOW')}`;

  const fileLoc = f.in_git_history
    ? `git:${f.commit_hash || '?'} · line ${f.line || '?'}`
    : `${f.file || '?'}:${f.line || '?'}`;

  const tags = [
    f.in_git_history ? '<span class="tag tag-git">git history</span>' : '',
    f.in_comment     ? '<span class="tag tag-comment">in comment</span>' : '',
  ].filter(Boolean).join('');

  const entropyLabel = (f.entropy && f.entropy.label) || 'low';
  const entropyScore = (f.entropy && f.entropy.score != null) ? f.entropy.score : '—';

  const commitBlock = (f.in_git_history && f.commit_hash) ? `
    <div class="f-label">Commit</div>
    <div class="f-meta">
      <div class="f-meta-item">
        <span class="f-meta-key">Hash</span>
        <span class="f-meta-val">${esc(f.commit_hash)}</span>
      </div>
      ${f.commit_date ? `
      <div class="f-meta-item">
        <span class="f-meta-key">Date</span>
        <span class="f-meta-val">${esc(String(f.commit_date).slice(0, 10))}</span>
      </div>` : ''}
      ${f.commit_message ? `
      <div class="f-meta-item" style="flex:1;min-width:0">
        <span class="f-meta-key">Message</span>
        <span class="f-meta-val" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:440px">${esc(f.commit_message)}</span>
      </div>` : ''}
    </div>` : '';

  card.innerHTML = `
    <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
      <span class="sev-badge badge-${esc(f.severity)}">${esc(f.severity || '?')}</span>
      <span class="finding-name">${esc(f.name || 'Unknown finding')}</span>
      <span class="finding-file">${esc(fileLoc)}</span>
      <svg class="finding-chevron" width="14" height="14" viewBox="0 0 24 24"
           fill="none" stroke="currentColor" stroke-width="2.2">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="finding-body">
      ${tags ? `<div class="tag-row">${tags}</div>` : ''}

      <div class="f-label">Detected value (redacted)</div>
      <div class="f-value">${esc(f.redacted_value || '—')}</div>

      <div class="f-label">Source line</div>
      <div class="f-code">${esc((f.line_content || '').trim() || '(no source line)')}</div>

      <div class="f-label">Analysis</div>
      <div class="f-meta">
        <div class="f-meta-item">
          <span class="f-meta-key">Entropy</span>
          <span class="f-meta-val entropy-${esc(entropyLabel)}">
            ${esc(String(entropyScore))}&nbsp;<span style="color:var(--text-dim)">(${esc(entropyLabel)})</span>
          </span>
        </div>
        <div class="f-meta-item">
          <span class="f-meta-key">Category</span>
          <span class="f-meta-val">${esc(f.category || '—')}</span>
        </div>
        <div class="f-meta-item">
          <span class="f-meta-key">Pattern ID</span>
          <span class="f-meta-val" style="color:var(--text-dim)">${esc(f.pattern_id || '—')}</span>
        </div>
      </div>

      ${commitBlock}

      <div class="f-label">Remediation</div>
      <div class="f-remedy">${esc(f.remediation || 'Rotate this credential immediately, then remove it from the repository and its full git history.')}</div>
    </div>`;

  return card;
}

/* ── filter buttons ─────────────────────────────────────────────────────── */
function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings();
}

/* kick off */
loadReport();
