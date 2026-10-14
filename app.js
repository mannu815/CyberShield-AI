const $ = (id) => document.getElementById(id);
const form = $('scan-form');
const scanButton = $('scan-button');
const scanMessage = $('scan-message');
let scans = [];
let latestScan = null;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function countsOf(scan) {
  if (scan && scan.counts) return scan.counts;
  const counts = {Critical:0,High:0,Medium:0,Low:0,Informational:0};
  (scan?.findings || []).forEach(f => { const key = String(f.severity || 'Informational'); if (key in counts) counts[key]++; });
  return counts;
}
function severityClass(severity) {
  return 'tag-' + String(severity || 'informational').toLowerCase().replace(/[^a-z]/g,'');
}
function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeHtml(value) : date.toLocaleString();
}
function normalizeScans(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.scans)) return payload.scans;
  if (payload && Array.isArray(payload.items)) return payload.items;
  return [];
}
async function api(path, options = {}) {
  const response = await fetch(path, options);
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const detail = data?.detail;
    const message = typeof detail === 'string' ? detail : detail ? JSON.stringify(detail) : `HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}
function renderStats() {
  $('stat-total').textContent = scans.length;
  const totals = {Critical:0,High:0,Medium:0};
  scans.forEach(s => { const c = countsOf(s); Object.keys(totals).forEach(k => totals[k] += Number(c[k] || 0)); });
  $('stat-critical').textContent = totals.Critical;
  $('stat-high').textContent = totals.High;
  $('stat-medium').textContent = totals.Medium;
}
function renderHistory() {
  const body = $('history-body');
  $('history-count').textContent = `${scans.length} record${scans.length === 1 ? '' : 's'}`;
  if (!scans.length) {
    body.innerHTML = '<tr><td colspan="6" class="table-empty">No scans saved yet. Run your first authorized passive scan above.</td></tr>';
    return;
  }
  body.innerHTML = scans.map(scan => {
    const c = countsOf(scan);
    const findings = Object.values(c).reduce((a,b) => a + Number(b || 0), 0);
    const target = scan.target || scan.final_url || 'Unknown target';
    return `<tr><td class="target-cell" title="${escapeHtml(target)}">${escapeHtml(target)}</td><td>${formatDate(scan.scanned_at)}</td><td class="http-good">${escapeHtml(scan.status_code ?? '—')}</td><td>${findings}</td><td>${escapeHtml(scan.mode || 'Passive')}</td><td><button class="view-button" data-scan-id="${escapeHtml(scan.id)}">View report ↗</button></td></tr>`;
  }).join('');
  body.querySelectorAll('[data-scan-id]').forEach(button => button.addEventListener('click', () => openReport(button.dataset.scanId)));
}
function renderLatest(scan) {
  if (!scan) return;
  latestScan = scan;
  $('latest-result').classList.add('hidden');
  const c = countsOf(scan);
  const findings = scan.findings || [];
  $('latest-details').classList.remove('hidden');
  $('latest-details').innerHTML = `<div class="target-line">${escapeHtml(scan.target || scan.final_url || 'Unknown target')}</div>
    <div class="latest-meta"><div class="mini-metric"><span>HTTP status</span><b>${escapeHtml(scan.status_code ?? '—')}</b></div><div class="mini-metric"><span>Duration</span><b>${Number(scan.duration_ms || 0) ? (Number(scan.duration_ms)/1000).toFixed(2)+'s' : '—'}</b></div><div class="mini-metric"><span>Total findings</span><b>${findings.length || Object.values(c).reduce((a,b)=>a+Number(b||0),0)}</b></div></div>
    <div class="latest-findings">${findings.slice(0,4).map(f => `<div class="finding-row"><span class="severity-tag ${severityClass(f.severity)}">${escapeHtml(f.severity)}</span><span>${escapeHtml(f.title)}</span></div>`).join('') || '<span class="finding-row">No finding details were returned by the API.</span>'}</div>
    <button class="secondary-button" id="latest-view-button" type="button">Open full report →</button>`;
  $('latest-view-button').addEventListener('click', () => showReport(scan));
}
async function loadHistory() {
  $('history-body').innerHTML = '<tr><td colspan="6" class="table-empty">Loading scan history…</td></tr>';
  try {
    const payload = await api('/api/scans');
    scans = normalizeScans(payload).sort((a,b) => new Date(b.scanned_at || 0) - new Date(a.scanned_at || 0));
    renderStats(); renderHistory();
    if (scans.length && !latestScan) renderLatest(scans[0]);
  } catch (error) {
    $('history-body').innerHTML = `<tr><td colspan="6" class="table-empty">Could not load scan history: ${escapeHtml(error.message)}. Check GET /api/scans in /docs.</td></tr>`;
    $('history-count').textContent = 'API error';
    $('stat-total').textContent = '—';
  }
}
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const target = $('target').value.trim();
  if (!$('authorized').checked) { scanMessage.textContent = 'Please confirm you have permission to assess this target.'; scanMessage.className = 'message error'; return; }
  if (!/^https?:\/\//i.test(target)) { scanMessage.textContent = 'Enter a complete URL beginning with https:// or http://'; scanMessage.className = 'message error'; return; }
  scanButton.disabled = true; scanButton.innerHTML = '<span>◌</span> Scanning…';
  scanMessage.className = 'message'; scanMessage.textContent = 'Running passive checks. Please wait…';
  try {
    // Backend schema uses form fields: target and authorized (string).
    const body = new URLSearchParams({target, authorized:'yes'});
    const result = await api('/api/scans', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'}, body});
    renderLatest(result);
    scanMessage.textContent = `Scan completed successfully (HTTP ${result.status_code ?? 'response received'}).`;
    await loadHistory();
    renderLatest(result);
  } catch (error) {
    scanMessage.className = 'message error';
    scanMessage.textContent = `Scan failed: ${error.message}`;
  } finally {
    scanButton.disabled = false; scanButton.innerHTML = '<span>⌁</span> Run passive scan <span class="button-arrow">→</span>';
  }
});
$('refresh-button').addEventListener('click', loadHistory);
function showReport(scan) {
  const c = countsOf(scan);
  const summary = ['Critical','High','Medium','Low'].map(s => `<div class="mini-metric"><span>${s}</span><b>${Number(c[s]||0)}</b></div>`).join('');
  const findings = (scan.findings || []).map(f => `<article class="report-finding"><div class="report-finding-top"><span class="severity-tag ${severityClass(f.severity)}">${escapeHtml(f.severity)}</span><h4>${escapeHtml(f.title)}</h4></div><p><b>Status:</b> ${escapeHtml(f.status || '—')}</p><p><b>Category:</b> ${escapeHtml(f.category || '—')}</p><p><b>Evidence:</b> ${escapeHtml(f.evidence || '—')}</p><p><b>Recommendation:</b> ${escapeHtml(f.recommendation || '—')}</p></article>`).join('');
  $('modal-title').textContent = `Scan #${scan.id ?? ''} report`;
  $('modal-content').innerHTML = `<div class="modal-meta">Target: ${escapeHtml(scan.target || '—')} · Final URL: ${escapeHtml(scan.final_url || '—')}<br>Scanned: ${formatDate(scan.scanned_at)} · HTTP: ${escapeHtml(scan.status_code ?? '—')} · Duration: ${escapeHtml(scan.duration_ms ?? '—')} ms<br>Mode: ${escapeHtml(scan.mode || 'Passive checks only')}</div><div class="report-summary">${summary}</div><div class="report-findings">${findings || '<div class="table-empty">No finding details were returned.</div>'}</div><p class="modal-meta" style="margin-top:18px">Passive checks are indicators, not proof of exploitability. This report does not replace an authorized full security assessment.</p>`;
  $('detail-modal').classList.remove('hidden');
}
async function openReport(id) {
  try {
    const detail = await api(`/api/scans/${encodeURIComponent(id)}`);
    showReport(detail);
  } catch (error) {
    const cached = scans.find(s => String(s.id) === String(id));
    if (cached?.findings) showReport(cached);
    else { scanMessage.className='message error'; scanMessage.textContent=`Could not load report: ${error.message}`; }
  }
}
$('modal-close').addEventListener('click', () => $('detail-modal').classList.add('hidden'));
$('detail-modal').addEventListener('click', (event) => { if (event.target === $('detail-modal')) $('detail-modal').classList.add('hidden'); });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') $('detail-modal').classList.add('hidden'); });
loadHistory();
