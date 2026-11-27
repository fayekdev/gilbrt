'use strict';
const $ = selector => document.querySelector(selector);
const all = selector => [...document.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const checkNames = {'passwords':'Passwords','api-keys':'API keys','tokens':'Tokens','private-keys':'Private keys','entropy':'High-entropy values','comments':'Comments','endpoints':'Endpoint references','headers':'Security headers','tls':'TLS','breaches':'Breach catalogue','access-codes':'Access codes','connections':'Connection strings','browser-code':'Browser code','forms':'Forms'};
const PAGE_SIZE = 40;
let token = '', settings = null, checks = [], sourceChecks = [], models = [{id:'',name:'Static checks only'}];
let report = null, reportId = '', job = null, mode = 'website', connected = false, booting = false;
let pollTimer, toastTimer, lastTerminal = '', findingPage = 0, resourcePage = 0, detailIndex = -1, evidenceRequest = 0;

async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(15000),
      headers: {'X-Gilbrt-Token':token, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      ...(body === undefined ? {} : {body:JSON.stringify(body)})
    });
  } catch {
    connection(false);
    throw Error('Engine unavailable. Start gilbrt --gui, then reconnect.');
  }
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Request failed.');
  return data;
}
function notify(message) {
  clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').hidden = false;
  toastTimer = setTimeout(() => $('#toast').hidden = true, 4000);
}
function connection(ok, message = '') {
  connected = ok;
  $('#engine-status').className = `engine-status ${ok ? 'ready' : 'disconnected'}`;
  $('#engine-status').innerHTML = `<i></i>${ok ? 'Engine connected' : 'Engine unavailable'}`;
  $('#connection-notice').hidden = ok;
  $('#connection-message').textContent = message || 'Start gilbrt --gui, then reconnect.';
  $('#new-audit').disabled = !ok;
  all('[data-start]').forEach(button => button.disabled = !ok);
  $('#settings-form button[type=submit]').disabled = !ok;
}
function navigate(page) {
  if (!['overview','findings','coverage','settings'].includes(page)) page = 'overview';
  all('.page').forEach(element => element.hidden = element.id !== `${page}-page`);
  all('[data-page]').forEach(element => {
    const active = element.dataset.page === page;
    element.classList.toggle('active', active);
    if (active) element.setAttribute('aria-current','page'); else element.removeAttribute('aria-current');
  });
  const title = {overview:'Audit',findings:'Findings',coverage:'Resources',settings:'Settings'}[page];
  $('#page-title').innerHTML = `${title}<span>.</span>`;
  $('#breadcrumb').textContent = title.toLowerCase();
  $('#page-description').textContent = {overview:'Website source, headers and TLS.',findings:'Evidence and remediation.',coverage:'Scanned resources and coverage notes.',settings:'Defaults for your next audit.'}[page];
  document.title = `gilbrt — ${title}`;
  window.scrollTo(0,0);
}
function findings() { return report?.findings || []; }
function badge(severity) { return `<span class="badge ${escapeHTML(severity.toLowerCase())}">${escapeHTML(severity)}</span>`; }
function findingRows(items) {
  return items.map(finding => `<button class="finding-row" data-finding="${finding.index}">${badge(finding.severity)}<span class="finding-copy"><span class="finding-title">${escapeHTML(finding.title)}</span><span class="finding-meta">${escapeHTML(finding.url)}</span></span><span class="finding-category">${escapeHTML(finding.category)}</span>${icon('chevron')}</button>`).join('');
}
function pagination(prefix, total, page) {
  $(`#${prefix}-pagination`).hidden = total <= PAGE_SIZE;
  $(`#${prefix}-prev`).disabled = page === 0;
  $(`#${prefix}-next`).disabled = (page+1)*PAGE_SIZE >= total;
  $(`#${prefix}-page`).textContent = `${page+1} / ${Math.max(1, Math.ceil(total/PAGE_SIZE))}`;
}
function renderFindings() {
  const query = $('#search').value.trim().toLowerCase(), severity = $('#severity').value, category = $('#category').value;
  const selected = findings().filter(finding => (severity === 'all' || finding.severity === severity) && (category === 'all' || finding.category === category) && (!query || [finding.title,finding.category,finding.evidence,finding.url].some(value => value.toLowerCase().includes(query))));
  findingPage = Math.min(findingPage, Math.max(0,Math.ceil(selected.length/PAGE_SIZE)-1));
  $('#results-count').textContent = `${selected.length} ${selected.length === 1 ? 'finding' : 'findings'}${selected.length !== findings().length ? ` of ${findings().length}` : ''}`;
  $('#all-findings').innerHTML = findingRows(selected.slice(findingPage*PAGE_SIZE, (findingPage+1)*PAGE_SIZE)) || `<p class="list-empty">${report ? 'No matching findings.' : 'Run an audit to see findings.'}</p>`;
  $('#clear-filters').hidden = !query && severity === 'all' && category === 'all';
  pagination('finding',selected.length,findingPage);
}
function renderResources() {
  const meta = report?.metadata || {}, items = meta.resource_inventory || [], local = meta.mode === 'files';
  resourcePage = Math.min(resourcePage, Math.max(0,Math.ceil(items.length/PAGE_SIZE)-1));
  $('#coverage-total').textContent = report ? `${items.length} scanned` : '';
  $('#coverage-note').textContent = !report ? 'Run an audit to see resources.' : local ? 'Selected files only. Headers, TLS and breach checks are unavailable.' : `${meta.resources_scanned} scanned of ${meta.resources_attempted ?? items.length} attempted. JavaScript is not executed; authenticated pages are not crawled.`;
  $('#resource-list').innerHTML = items.slice(resourcePage*PAGE_SIZE,(resourcePage+1)*PAGE_SIZE).map(item => `<div class="resource-row"><strong>${escapeHTML(item.resource)}</strong><span>${escapeHTML(item.kind)}${item.status == null ? '' : ` · HTTP ${Number(item.status)}`}</span><small>${(Number(item.bytes)/1024).toFixed(1)} KiB</small></div>`).join('') || '<p class="list-empty">No scanned resources.</p>';
  const notes = findings().filter(finding => finding.category === 'Coverage');
  $('#coverage-observations').hidden = !notes.length;
  $('#coverage-list').innerHTML = notes.map(finding => `<article class="coverage-note"><h3>${escapeHTML(finding.title)}</h3><p>${escapeHTML(finding.evidence)}</p><p>${escapeHTML(finding.remediation)}</p></article>`).join('');
  pagination('resource',items.length,resourcePage);
}
function renderActivity() {
  $('#activity-events').innerHTML = (job?.events || []).slice(-8).reverse().map(event => `<div><span>${Number(event.elapsed).toFixed(1)}s</span><strong>${escapeHTML(event.stage)}</strong></div>`).join('') || '<p class="field-hint">No activity recorded.</p>';
}
function render() {
  $('#empty-state').hidden = !!report; $('#audit-results').hidden = !report;
  $('#export-top').disabled = !report || !connected;
  $('#nav-count').textContent = findings().length; $('#nav-count').hidden = !findings().length;
  for (const severity of ['Critical','Warning','Info']) $(`#${severity.toLowerCase()}-count`).textContent = findings().filter(finding => finding.severity === severity).length;
  if (report) {
    const meta = report.metadata, local = meta.mode === 'files', assessment = report.assessment || {};
    $('#target-name').textContent = report.session?.target_origin || meta.target;
    $('#session-icon use').setAttribute('href',local ? '#i-files' : '#i-globe');
    $('#target-meta').textContent = local ? 'Local files · static source inspection' : `Passive website audit · ${meta.robots_respected ? 'robots.txt respected' : 'robots.txt override'}`;
    $('#target-status').textContent = assessment.status === 'source_scan_failed' ? 'No source scanned' : assessment.status === 'partial' ? 'Partial coverage' : 'Finished';
    $('#resource-count').textContent = meta.resources_scanned;
    $('#resource-summary').textContent = `${meta.resources_attempted ?? meta.resources_scanned} attempted`;
    $('#assessment').hidden = !['source_scan_failed','partial'].includes(assessment.status);
    $('#assessment').textContent = assessment.status === 'source_scan_failed' ? 'No source scanned. Review Resources for errors.' : 'Coverage is incomplete. Review Resources before interpreting the findings.';
    $('#priority-list').innerHTML = findingRows(findings().slice(0,5)) || '<p class="list-empty">No findings in the scanned resources.</p>';
    const ai = meta.local_ai || {}, duration = Number(report.session?.elapsed || 0).toFixed(1);
    const details = [['Source',local ? 'Local files' : 'Website'],['Duration',`${duration}s`],['Checks',(meta.search_categories || []).filter(check => check !== 'local-ai').length],['Model',ai.enabled ? `${ai.backend} · ${ai.chunks_analyzed} reviewed` : ai.requested ? 'Skipped' : 'Off']];
    if (ai.failed) details.push(['Model status','Review failed']);
    if (!local) details.push(['Resource limit',meta.max_pages]);
    $('#run-details').innerHTML = details.map(([label,value]) => `<div><dt>${label}</dt><dd>${escapeHTML(value)}</dd></div>`).join('');
  }
  const selectedCategory = $('#category').value;
  $('#category').innerHTML = '<option value="all">All categories</option>' + [...new Set(findings().map(finding => finding.category))].sort().map(category => `<option value="${escapeHTML(category)}">${escapeHTML(category)}</option>`).join('');
  $('#category').value = [...$('#category').options].some(option => option.value === selectedCategory) ? selectedCategory : 'all';
  renderFindings(); renderResources(); renderActivity();
}
function acceptReport(data) {
  if (!Object.hasOwn(data,'report')) return;
  report = data.report; reportId = data.report_id || ''; findingPage = 0; resourcePage = 0;
  report?.findings.forEach((finding,index) => finding.index = index);
}
function renderChecks(selector, selected) {
  $(selector).innerHTML = checks.map(check => {
    const disabled = selector === '#audit-checks' && mode === 'files' && !sourceChecks.includes(check);
    return `<label class="${disabled ? 'disabled' : ''}"><input type="checkbox" value="${escapeHTML(check)}" ${selected.includes(check) && !disabled ? 'checked' : ''} ${disabled ? 'disabled' : ''}><span>${escapeHTML(checkNames[check] || check)}</span></label>`;
  }).join('');
}
function setModels(selector,value) {
  const list = [...models];
  if (value && !list.some(model => model.id === value)) list.push({id:value,name:`${value} (unavailable)`});
  $(selector).innerHTML = list.map(model => `<option value="${escapeHTML(model.id)}">${escapeHTML(model.name)}</option>`).join('');
  $(selector).value = value;
}
function fillSettings() {
  for (const [name,value] of Object.entries(settings)) {
    const field = $('#settings-form').elements.namedItem(name); if (!field) continue;
    if (field.type === 'checkbox') field.checked = value; else field.value = value ?? '';
  }
  renderChecks('#settings-checks',settings.checks); setModels('#settings-model',settings.model);
}
async function refreshModels() {
  const button = $('#refresh-models'); button.disabled = true; $('#model-status').textContent = 'Checking local models…';
  try {
    const data = await api(`/api/models?url=${encodeURIComponent($('#ollama-url').value)}`);
    models = data.choices;
    setModels('#settings-model',$('#settings-model').value);
    setModels('#audit-model',$('#audit-model').value || settings.model);
    const installed = models.length-1;
    $('#model-status').textContent = installed ? `${installed} installed ${installed === 1 ? 'model' : 'models'}.${data.available_memory_bytes ? ` ${(data.available_memory_bytes/1024**3).toFixed(1)} GiB available RAM.` : ''}` : 'No installed models. Static checks are available.';
  } catch (error) { $('#model-status').textContent = error.message; }
  finally { button.disabled = false; }
}
function readSettings() {
  const form = $('#settings-form'), result = {...settings};
  for (const key of ['max_pages','max_depth','max_resource_mb','rate_limit','ai_candidate_limit']) result[key] = Number(form.elements.namedItem(key).value);
  result.ai_max_chunks = form.elements.namedItem('ai_max_chunks').value === '' ? null : Number(form.elements.namedItem('ai_max_chunks').value);
  for (const key of ['model','ollama_url','export_format']) result[key] = form.elements.namedItem(key).value;
  result.ignore_robots = form.elements.namedItem('ignore_robots').checked;
  result.checks = all('#settings-checks input:checked').map(input => input.value);
  return result;
}
async function saveSettings(event) {
  event.preventDefault(); const button = $('#settings-form button[type=submit]'); button.disabled = true;
  $('#settings-error').textContent = '';
  try { settings = (await api('/api/settings',readSettings())).settings; fillSettings(); notify('Settings saved.'); }
  catch (error) { $('#settings-error').textContent = error.message; }
  finally { button.disabled = false; }
}
function selectMode(value) {
  const selected = all('#audit-checks input:checked').map(input => input.value);
  mode = value;
  all('[data-mode]').forEach(button => button.setAttribute('aria-pressed',String(button.dataset.mode === mode)));
  $('#website-fields').hidden = mode !== 'website'; $('#file-fields').hidden = mode !== 'files';
  $('#target').required = mode === 'website'; $('#target').disabled = mode !== 'website';
  $('#source-files').required = mode === 'files'; $('#source-files').disabled = mode !== 'files';
  $('#extra-resources').hidden = mode === 'files';
  $('#authorization-label').textContent = mode === 'files' ? 'I own these files or have permission to inspect them.' : 'I own this website or have permission to audit it.';
  renderChecks('#audit-checks',selected.length ? selected : settings.checks);
  $('#audit-config-summary').textContent = mode === 'files' ? `${settings.max_pages} file limit · ${settings.max_resource_mb} MiB per file · no website requests` : `${settings.max_pages} resources · depth ${settings.max_depth} · ${settings.rate_limit}s delay`;
}
function openSetup() {
  if (!connected) return notify('Start gilbrt --gui, then reconnect.');
  if (job && ['running','cancelling'].includes(job.status)) { updateScan(); $('#scan-dialog').showModal(); return; }
  renderChecks('#audit-checks',settings.checks); selectMode(mode); setModels('#audit-model',settings.model);
  $('#form-error').textContent = ''; $('#authorization').checked = false;
  $('#setup-dialog').showModal();
}
async function startAudit(event) {
  event.preventDefault(); const button = $('#start-audit'); button.disabled = true; $('#form-error').textContent = '';
  const selectedMode = mode;
  try {
    const options = {...settings,model:$('#audit-model').value,checks:all('#audit-checks input:checked').map(input => input.value)};
    if (!options.checks.length) throw Error('Select at least one check.');
    const data = {authorized:$('#authorization').checked,settings:options};
    if (selectedMode === 'files') {
      const files = [...$('#source-files').files];
      if (!files.length || files.length > 100) throw Error('Choose 1–100 source files.');
      if (files.reduce((total,file) => total+file.size,0) > 16*1024**2) throw Error('Selected files exceed 16 MiB.');
      data.files = await Promise.all(files.map(async file => ({name:file.name,content:await file.text()})));
      if (new TextEncoder().encode(JSON.stringify(data)).length > 32*1024**2) throw Error('Encoded files exceed the upload limit. Select fewer files.');
    } else {
      data.target = $('#target').value;
      data.include_urls = $('#include-urls').value.split('\n').map(line => line.trim()).filter(Boolean);
    }
    const response = await api(selectedMode === 'files' ? '/api/offline' : '/api/audit',data);
    job = response.job; $('#setup-dialog').close(); updateScan(); $('#scan-dialog').showModal(); schedulePoll(300);
  } catch (error) { $('#form-error').textContent = error.message; }
  finally { button.disabled = false; }
}
function updateScan() {
  if (!job) return;
  $('#scan-target').textContent = job.mode === 'files' ? 'Local source files' : (() => {try { return new URL(job.target).origin; } catch { return 'Website'; }})();
  $('#scan-stage').textContent = job.stage;
  $('#scan-count').textContent = `${job.resources_scanned} scanned`;
  $('#scan-log').innerHTML = (job.events || []).slice(-5).map(event => `<div>${Number(event.elapsed).toFixed(1)}s · ${escapeHTML(event.stage)}${event.batch ? ` · batch ${event.batch}` : ''}</div>`).join('');
  $('#cancel-scan').disabled = job.status === 'cancelling'; $('#cancel-scan').textContent = job.status === 'cancelling' ? 'Stopping…' : 'Cancel audit';
}
function schedulePoll(delay = document.hidden ? 3500 : 800) { clearTimeout(pollTimer); pollTimer = setTimeout(poll,delay); }
async function poll() {
  try {
    const data = await api(`/api/state?report_id=${encodeURIComponent(reportId)}`);
    connection(true); job = data.job; acceptReport(data);
    if (job && ['running','cancelling'].includes(job.status)) { updateScan(); renderActivity(); schedulePoll(); return; }
    if ($('#scan-dialog').open) $('#scan-dialog').close();
    const terminal = job ? `${job.id}:${job.status}` : '';
    if (terminal && terminal !== lastTerminal) {
      lastTerminal = terminal; render();
      if (job.status === 'complete') { location.hash = 'overview'; navigate('overview'); notify('Audit finished.'); }
      else notify(job.status === 'cancelled' ? 'Audit cancelled.' : job.error || 'Audit failed.');
    }
  } catch (error) { connection(false,error.message); $('#scan-stage').textContent = 'Engine disconnected'; }
}
async function cancelAudit() {
  if (!job || !['running','cancelling'].includes(job.status)) return;
  try { job = (await api('/api/cancel',{})).job; updateScan(); schedulePoll(300); }
  catch (error) { connection(false,error.message); }
}
function showFinding(index) {
  const finding = report?.findings[index]; if (!finding) return;
  detailIndex = index; evidenceRequest++;
  $('#detail-severity').className = `badge ${finding.severity.toLowerCase()}`;
  $('#detail-severity').textContent = finding.severity;
  $('#detail-title').textContent = finding.title; $('#detail-category').textContent = finding.category;
  $('#detail-evidence').textContent = finding.evidence; $('#detail-resource').textContent = finding.url;
  $('#detail-remediation').textContent = finding.remediation;
  $('#reveal-evidence').hidden = !['Password','Access code','Secret','Connection','Local AI'].includes(finding.category);
  $('#reveal-evidence').disabled = false;
  $('#reveal-evidence').innerHTML = `${icon('eye')}Show matched value`;
  $('#finding-dialog').showModal();
}
async function revealEvidence() {
  const request = ++evidenceRequest, button = $('#reveal-evidence'); button.disabled = true;
  try {
    const data = await api(`/api/evidence?report_id=${encodeURIComponent(reportId)}&index=${detailIndex}`);
    if (request !== evidenceRequest || !$('#finding-dialog').open) return;
    $('#detail-evidence').textContent = data.evidence;
    button.textContent = 'Value shown locally';
  } catch (error) { if (request === evidenceRequest) { button.disabled = false; notify(error.message); } }
}
async function downloadReport() {
  const button = $('#download-report'); button.disabled = true;
  try {
    const format = $('#export-format').value;
    const response = await fetch(`/api/export?format=${format}`,{headers:{'X-Gilbrt-Token':token},signal:AbortSignal.timeout(15000)});
    if (!response.ok) throw Error((await response.json()).error || 'Export failed.');
    const url = URL.createObjectURL(await response.blob()), link = document.createElement('a');
    link.href = url; link.download = `gilbrt-report.${format === 'ai' ? 'md' : format}`; link.click();
    setTimeout(() => URL.revokeObjectURL(url),1000); $('#export-dialog').close(); notify('Report exported.');
  } catch (error) { notify(error.message); } finally { button.disabled = false; }
}
async function initialize() {
  if (booting) return; booting = true; clearTimeout(pollTimer);
  try {
    const response = await fetch('/api/bootstrap',{signal:AbortSignal.timeout(10000)});
    const data = await response.json(); if (!response.ok) throw Error(data.error || 'Engine unavailable.');
    token = data.token; settings = data.settings; checks = data.checks;
    sourceChecks = data.content_checks || checks.filter(check => !['headers','tls','breaches'].includes(check));
    job = data.job; acceptReport(data); connection(true); fillSettings(); render();
    $('#hibp-status').textContent = data.hibp_available ? 'Breach catalogue uses HIBP and requires internet.' : 'Breach catalogue requires internet and HIBP_API_KEY.';
    refreshModels();
    if (job && ['running','cancelling'].includes(job.status)) { updateScan(); if (!$('#scan-dialog').open) $('#scan-dialog').showModal(); schedulePoll(); }
    else { if ($('#scan-dialog').open) $('#scan-dialog').close(); lastTerminal = job ? `${job.id}:${job.status}` : ''; }
  } catch (error) { connection(false,error.message); } finally { booting = false; }
}

document.addEventListener('click',event => {
  const finding = event.target.closest('[data-finding]'); if (finding) showFinding(Number(finding.dataset.finding));
  const go = event.target.closest('[data-go]'); if (go) location.hash = go.dataset.go;
  const severity = event.target.closest('[data-severity]');
  if (severity) { $('#severity').value = severity.dataset.severity; $('#search').value = ''; $('#category').value = 'all'; findingPage = 0; renderFindings(); location.hash = 'findings'; }
  const close = event.target.closest('[data-close]'); if (close) close.closest('dialog').close();
  const start = event.target.closest('[data-start]'); if (start) openSetup();
  const source = event.target.closest('[data-mode]'); if (source) selectMode(source.dataset.mode);
});
window.addEventListener('hashchange',() => { if (location.hash !== '#main') navigate(location.hash.slice(1)); });
$('#new-audit').addEventListener('click',openSetup);
$('#setup-form').addEventListener('submit',startAudit);
$('#settings-form').addEventListener('submit',saveSettings);
$('#refresh-models').addEventListener('click',refreshModels);
$('#reconnect').addEventListener('click',initialize);
$('#cancel-scan').addEventListener('click',cancelAudit);
$('#scan-dialog').addEventListener('cancel',event => { event.preventDefault(); cancelAudit(); });
$('#reveal-evidence').addEventListener('click',revealEvidence);
$('#finding-dialog').addEventListener('close',() => { evidenceRequest++; detailIndex = -1; $('#detail-evidence').textContent = ''; });
$('#export-top').addEventListener('click',() => { $('#export-format').value = settings.export_format; $('#export-dialog').showModal(); });
$('#download-report').addEventListener('click',downloadReport);
for (const id of ['search','severity','category']) $(`#${id}`).addEventListener(id === 'search' ? 'input' : 'change',() => { findingPage = 0; renderFindings(); });
$('#clear-filters').addEventListener('click',() => { $('#search').value = ''; $('#severity').value = 'all'; $('#category').value = 'all'; findingPage = 0; renderFindings(); });
for (const [prefix,renderPage] of [['finding',renderFindings],['resource',renderResources]]) {
  for (const [direction,delta] of [['prev',-1],['next',1]]) $(`#${prefix}-${direction}`).addEventListener('click',() => {
    if (prefix === 'finding') findingPage = Math.max(0,findingPage+delta); else resourcePage = Math.max(0,resourcePage+delta); renderPage();
  });
}
$('#toggle-checks').addEventListener('click',() => { const inputs = all('#audit-checks input:not(:disabled)'), select = inputs.some(input => !input.checked); inputs.forEach(input => input.checked = select); $('#toggle-checks').textContent = select ? 'Clear all' : 'Select all'; });
$('#source-files').addEventListener('change',() => { const files = [...$('#source-files').files]; $('#file-summary').textContent = files.length ? `${files.length} files · ${(files.reduce((total,file) => total+file.size,0)/1024).toFixed(1)} KiB` : 'Up to 100 files · 16 MiB combined.'; });
$('#reset-settings').addEventListener('click',() => {
  const form = $('#settings-form');
  for (const [name,value] of Object.entries({max_pages:25,max_depth:2,max_resource_mb:16,rate_limit:1,ollama_url:'http://127.0.0.1:11434',ai_max_chunks:'',ai_candidate_limit:256,export_format:'json',model:''})) form.elements.namedItem(name).value = value;
  form.elements.namedItem('ignore_robots').checked = false; renderChecks('#settings-checks',checks); notify('Defaults restored. Save to apply.');
});
render(); navigate(location.hash.slice(1)); initialize();
