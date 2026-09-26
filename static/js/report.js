'use strict';

let R = null;          // report data
let activeFilter = 'ALL';

const SEV_COLORS = { CRITICAL:'#ef4444', HIGH:'#f06025', MEDIUM:'#f59e0b', LOW:'#60a5fa' };
const SEV_ORDER  = ['CRITICAL','HIGH','MEDIUM','LOW'];

// ── Boot ───────────────────────────────────────────────────────────────────────
async function loadReport() {
  try {
    const r = await fetch('/api/report/' + SCAN_ID);
    if (!r.ok) throw new Error('Report not found (HTTP ' + r.status + ')');
    R = await r.json();
    render();
  } catch(e) {
    document.getElementById('loading-state').innerHTML =
      `<p style="color:var(--text-muted)">Failed to load: ${esc(e.message)}</p>`;
  }
}

function render() {
  document.getElementById('loading-state').classList.add('hidden');
  document.getElementById('report-content').classList.remove('hidden');

  // nav badge
  document.getElementById('report-id-badge').textContent = 'Scan #' + SCAN_ID;

  // header
  document.getElementById('report-source').textContent = R.source || '';
  document.getElementById('report-meta').textContent =
    R.generated_at ? 'Scanned ' + new Date(R.generated_at).toLocaleString() : '';

  // scoreboard
  const s = R.summary || {};
  $('cnt-critical').textContent = s.critical || 0;
  $('cnt-high').textContent     = s.high     || 0;
  $('cnt-medium').textContent   = s.medium   || 0;
  $('cnt-low').textContent      = s.low      || 0;
  $('cnt-total').textContent    = s.total    || 0;

  renderDonut();
  renderCategoryBars();
  renderStatGrid();
  renderTopFiles();
  renderFindings();
}

// ── Donut chart (vanilla canvas) ──────────────────────────────────────────────
function renderDonut() {
  const s     = R.summary || {};
  const total = s.total || 1;
  const data  = SEV_ORDER.map(k => ({ label: k, val: s[k.toLowerCase()] || 0, color: SEV_COLORS[k] }))
                          .filter(d => d.val > 0);

  const canvas = document.getElementById('donut-chart');
  const ctx    = canvas.getContext('2d');
  const cx = 80, cy = 80, r = 62, hole = 42;

  ctx.clearRect(0, 0, 160, 160);

  if (data.length === 0) {
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI*2);
    ctx.strokeStyle = '#1e2228'; ctx.lineWidth = r - hole; ctx.stroke();
  } else {
    let angle = -Math.PI / 2;
    data.forEach(d => {
      const sweep = (d.val / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + sweep);
      ctx.closePath();
      ctx.fillStyle = d.color;
      ctx.fill();
      angle += sweep;
    });
    // punch hole
    ctx.beginPath(); ctx.arc(cx, cy, hole, 0, Math.PI*2);
    ctx.fillStyle = '#ffffff'; ctx.fill();
    // center text
    ctx.fillStyle = '#ffffff'; ctx.font = 'bold 20px Space Grotesk, sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(s.total || 0, cx, cy - 6);
    ctx.fillStyle = '#6b7280'; ctx.font = '11px Space Grotesk, sans-serif';
    ctx.fillText('findings', cx, cy + 12);
  }

  // legend
  const leg = $('donut-legend');
  leg.innerHTML = '';
  data.forEach(d => {
    const pct = total > 0 ? Math.round(d.val / total * 100) : 0;
    leg.insertAdjacentHTML('beforeend', `
      <div class="legend-row">
        <span class="legend-label"><span class="legend-dot" style="background:${d.color}"></span>${d.label}</span>
        <span class="legend-val">${d.val} <span class="legend-pct">${pct}%</span></span>
      </div>`);
  });
}

// ── Category bars ─────────────────────────────────────────────────────────────
function renderCategoryBars() {
  const cats = R.categories || {};
  const max  = Math.max(...Object.values(cats), 1);
  const el   = $('category-bars');
  el.innerHTML = '';
  Object.entries(cats)
    .sort((a,b) => b[1]-a[1])
    .forEach(([cat, count]) => {
      const pct = Math.round(count / max * 100);
      el.insertAdjacentHTML('beforeend', `
        <div class="cat-bar-row">
          <div class="cat-bar-label"><span>${esc(cat)}</span><span>${count}</span></div>
          <div class="cat-bar-track"><div class="cat-bar-fill" style="width:${pct}%"></div></div>
        </div>`);
    });
  if (!Object.keys(cats).length) el.innerHTML = '<p style="font-size:.78rem;color:var(--text-dim)">No findings</p>';
}

// ── Stat grid ─────────────────────────────────────────────────────────────────
function renderStatGrid() {
  const st  = R.stats || {};
  const el  = $('stat-grid');
  const dt  = R.generated_at ? new Date(R.generated_at) : null;
  const dur = (R.stats?.duration_seconds != null)
    ? R.stats.duration_seconds.toFixed(1) + 's'
    : '—';
  const cells = [
    ['Files scanned', (st.files_scanned ?? '—').toLocaleString()],
    ['Files skipped', (st.files_skipped ?? '—').toLocaleString()],
    ['Patterns run',  '30+'],
    ['Scan time',     dur],
  ];
  el.innerHTML = cells.map(([k,v]) => `
    <div class="stat-cell">
      <span class="stat-cell-val">${esc(String(v))}</span>
      <span class="stat-cell-key">${esc(k)}</span>
    </div>`).join('');
}

// ── Top affected files ────────────────────────────────────────────────────────
function renderTopFiles() {
  const findings = R.findings || [];
  const freq = {};
  findings.forEach(f => { if (f.file) freq[f.file] = (freq[f.file]||0)+1; });
  const sorted = Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const el = $('top-files');
  if (!sorted.length) { el.innerHTML = '<p style="font-size:.78rem;color:var(--text-dim)">No findings</p>'; return; }
  el.innerHTML = sorted.map(([file, count]) => {
    const short = file.split(/[/\\]/).pop() || file;
    return `<div class="top-file-row">
      <span class="top-file-name" title="${esc(file)}">${esc(short)}</span>
      <span class="top-file-badge">${count}</span>
    </div>`;
  }).join('');
}

// ── Findings list ─────────────────────────────────────────────────────────────
function renderFindings() {
  const search   = ($('search-input').value || '').toLowerCase();
  const all      = R.findings || [];
  const filtered = all.filter(f => {
    if (activeFilter !== 'ALL' && f.severity !== activeFilter) return false;
    if (search) {
      const hay = (f.name+f.file+f.category+f.pattern_id).toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  $('filter-count').textContent = filtered.length + ' of ' + all.length;
  const noF = $('no-findings');
  const list = $('findings-list');

  if (filtered.length === 0) {
    list.innerHTML = '';
    noF.classList.remove('hidden');
    return;
  }
  noF.classList.add('hidden');

  const frag = document.createDocumentFragment();
  const wrap = document.createElement('div');
  wrap.className = 'findings-stack';
  filtered.forEach(f => wrap.appendChild(buildCard(f)));
  frag.appendChild(wrap);
  list.innerHTML = '';
  list.appendChild(frag);
}

function buildCard(f) {
  const card = document.createElement('div');
  card.className = `finding-card sev-${f.severity}`;

  const fileLoc = f.in_git_history
    ? `git:${f.commit_hash} · line ${f.line}`
    : `${f.file}:${f.line}`;

  const tags = [
    f.in_git_history ? '<span class="tag tag-git">git history</span>' : '',
    f.in_comment     ? '<span class="tag tag-comment">in comment</span>' : '',
  ].join('');

  const commitBlock = (f.in_git_history && f.commit_hash) ? `
    <div class="f-label">Commit</div>
    <div class="f-meta">
      <div class="f-meta-item"><span class="f-meta-key">Hash</span><span class="f-meta-val">${esc(f.commit_hash)}</span></div>
      ${f.commit_date ? `<div class="f-meta-item"><span class="f-meta-key">Date</span><span class="f-meta-val">${esc(f.commit_date.slice(0,10))}</span></div>` : ''}
      ${f.commit_message ? `<div class="f-meta-item" style="flex:1"><span class="f-meta-key">Message</span><span class="f-meta-val" style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:440px">${esc(f.commit_message)}</span></div>` : ''}
    </div>` : '';

  card.innerHTML = `
    <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
      <span class="sev-badge badge-${f.severity}">${f.severity}</span>
      <span class="finding-name">${esc(f.name)}</span>
      <span class="finding-file">${esc(fileLoc)}</span>
      <svg class="finding-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="finding-body">
      ${tags ? `<div class="tag-row">${tags}</div>` : ''}

      <div class="f-label">Detected value (redacted)</div>
      <div class="f-value">${esc(f.redacted_value||'—')}</div>

      <div class="f-label">Source line</div>
      <div class="f-code">${esc((f.line_content||'').trim())}</div>

      <div class="f-label">Analysis</div>
      <div class="f-meta">
        <div class="f-meta-item">
          <span class="f-meta-key">Entropy</span>
          <span class="f-meta-val entropy-${f.entropy?.label||'low'}">${f.entropy?.score??'—'}&nbsp;<span style="color:var(--text-dim)">(${f.entropy?.label??'—'})</span></span>
        </div>
        <div class="f-meta-item">
          <span class="f-meta-key">Category</span>
          <span class="f-meta-val">${esc(f.category||'—')}</span>
        </div>
        <div class="f-meta-item">
          <span class="f-meta-key">Pattern ID</span>
          <span class="f-meta-val" style="color:var(--text-dim)">${esc(f.pattern_id||'—')}</span>
        </div>
      </div>

      ${commitBlock}

      <div class="f-label">Remediation</div>
      <div class="f-remedy">${esc(f.remediation||'—')}</div>
    </div>`;

  return card;
}

// ── Filter ────────────────────────────────────────────────────────────────────
function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings();
}

// ── PDF download ──────────────────────────────────────────────────────────────
function downloadPDF() {
  window.open('/api/report/' + SCAN_ID + '/download/pdf', '_blank');
}

// ── Util ───────────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

loadReport();
