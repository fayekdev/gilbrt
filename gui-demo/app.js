const $ = selector => document.querySelector(selector);
const all = selector => [...document.querySelectorAll(selector)];
const samples = [
  {id:1,severity:'Critical',category:'Passwords',group:'secrets',title:'Password exposed in client-side code',resource:'app.bundle.js · line 142',evidence:'const dbPassword = "[REDACTED]";\nResource digest: demo-a12b34c56d78',remediation:'Remove the password from the client bundle. Rotate the affected credential and move credential-dependent operations to a server. Review access logs for unexpected use.'},
  {id:2,severity:'Critical',category:'Private keys',group:'secrets',title:'Private key found in a public asset',resource:'config.js · line 38',evidence:'-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----',remediation:'Remove the private key from public assets and revoke or rotate it. Keep replacement keys in server-side secret storage and review how this file reached the build.'},
  {id:3,severity:'Warning',category:'API keys',group:'secrets',title:'Potential API key in JavaScript',resource:'vendor.js · line 806',evidence:'apiKey: "demo…[REDACTED]…0000"',remediation:'Confirm whether the key is intended for public client use. Apply provider restrictions where appropriate. If it is a server credential, rotate it and remove it from the bundle.'},
  {id:4,severity:'Warning',category:'Security headers',group:'headers',title:'Content Security Policy is missing',resource:'Root document · response headers',evidence:'Content-Security-Policy: [not present]',remediation:'Define a Content Security Policy appropriate for the application. Evaluate it with report-only mode before enforcement and restrict script sources to those the application requires.'},
  {id:5,severity:'Warning',category:'Access codes',group:'access',title:'Access code checked in the browser',resource:'gate.js · line 64',evidence:'if (accessPin === "[REDACTED]") {\n  unlockContent();\n}',remediation:'Enforce access checks on the server. A browser-visible comparison cannot protect sensitive content. Review whether protected data is already delivered before this check.'},
  {id:6,severity:'Info',category:'Tokens',group:'secrets',title:'Token-shaped value requires review',resource:'auth.js · line 211',evidence:'token: "[REDACTED TOKEN-SHAPED VALUE]"',remediation:'Determine whether this is synthetic data, an intentionally public value, or a usable credential. Remove and rotate any confidential token. This demo does not validate it against a provider.'}
];
let findings = [...samples];
let selectedChecks = ['secrets','headers','access','tls'];
let target = 'https://demo.gilbrt.example';
let scanTimer = null;
let completionTimer = null;
let toastTimer;
const colors = {Critical:'red',Warning:'yellow',Info:'blue'};
const safe = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
function pillClass(severity) { return severity === 'Warning' ? 'warning-pill' : colors[severity]; }
function row(finding) {
  return `<button class="finding-row" data-finding="${finding.id}"><span class="pill ${pillClass(finding.severity)}" ${finding.severity==='Warning'?'style="--color:var(--yellow)"':''}>${finding.severity.toUpperCase()}</span><span><span class="finding-title">${safe(finding.title)}</span><span class="finding-meta">${safe(finding.resource)}</span></span><span class="finding-category">${safe(finding.category)}</span><span class="row-open" aria-hidden="true">↗</span></button>`;
}
function render() {
  $('#priority-list').innerHTML = findings.slice(0,3).map(row).join('') || '<p class="empty">No findings for the selected demo checks.</p>';
  $('#nav-count').textContent = findings.length;
  $('#score-count').textContent = findings.length;
  ['Critical','Warning','Info'].forEach(level => $(`#${level.toLowerCase()}-count`).textContent = findings.filter(f=>f.severity===level).length);
  $('#secrets-total').textContent = findings.filter(f=>f.group==='secrets').length;
  $('#headers-total').textContent = findings.filter(f=>f.group==='headers').length;
  $('#access-total').textContent = findings.filter(f=>f.group==='access').length;
  all('.check-stat').forEach((el,index)=>{const count = findings.filter(f=>f.group===['secrets','headers','access'][index]).length;el.querySelector('i').style.width=`${count/5*100}%`;});
  const critical = findings.some(f=>f.severity==='Critical');
  const warning = findings.some(f=>f.severity==='Warning');
  const risk = $('.score-card .ring');
  risk.className = `ring ${critical?'red':warning?'blue':'mint'}`;
  risk.style.setProperty('--value',critical?72:warning?45:10);
  risk.querySelector('strong').textContent = critical?'HIGH':warning?'MED':'LOW';
  const scoreCopy = $('.score-card .score-copy');
  scoreCopy.innerHTML = `<span class="pill ${critical?'red':warning?'blue':'mint'}">${critical?'ACTION NEEDED':warning?'REVIEW NEEDED':'LIMITED FINDINGS'}</span><p>${critical?'Start with exposed<br> credentials.':warning?'Review flagged<br> configurations.':'Read coverage<br> before concluding.'}</p><small>${findings.filter(f=>f.severity==='Critical').length} critical candidates</small>`;
  const riskFoot = $('.score-card .card-foot span');
  riskFoot.textContent = findings.length ? 'Needs review' : 'Read coverage';
  riskFoot.className = findings.length ? 'red-text' : 'mint-text';
  $('#insight-copy').textContent = critical ? 'Review the exposed password and private key first. Remove them from client code and rotate affected credentials.' : findings.length ? 'Review the flagged configurations and confirm their impact. Coverage limitations still apply to this sample audit.' : 'No sample findings matched your selected checks. Review the coverage gaps before drawing conclusions.';
  $('#review-critical').textContent = critical?'Review critical':'Review findings';
  $('.checks-note').innerHTML = `TLS ${selectedChecks.includes('tls')?'checked':'not selected'} <span class="${selectedChecks.includes('tls')?'mint-text':''}">${selectedChecks.includes('tls')?'No sample findings':'Not assessed'}</span>`;
  renderFindings();
}
function renderFindings(){
  const query = $('#search').value.trim().toLowerCase();
  const severity = $('#severity').value;
  const filtered = findings.filter(f=>(severity==='all'||f.severity===severity)&&[f.title,f.category,f.evidence,f.resource].join(' ').toLowerCase().includes(query));
  $('#results-count').textContent = `${filtered.length} of ${findings.length} sample findings · values redacted`;
  $('#all-findings').innerHTML = filtered.map(row).join('') || '<p class="empty">No matching findings. Try another search or severity.</p>';
}
function navigate(page){
  if(!['overview','findings','coverage'].includes(page))page='overview';
  all('.page').forEach(el=>el.hidden=el.id!==`${page}-page`);
  all('[data-page]').forEach(el=>{el.classList.toggle('active',el.dataset.page===page);if(el.dataset.page===page)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
  $('#breadcrumb').textContent = page[0].toUpperCase()+page.slice(1);
  $('#page-title').innerHTML = `${{overview:'Audit overview',findings:'Your findings',coverage:'Audit coverage'}[page]}<span>.</span>`;
  $('#page-subtitle').textContent = {overview:'A clearer picture of your website’s exposure.',findings:'Look at the evidence. Decide what needs attention.',coverage:'Know what was scanned, and what was left unseen.'}[page];
  document.title = `gilbrt — ${$('#breadcrumb').textContent}`;
}
function notify(message){clearTimeout(toastTimer);$('#toast').textContent=message;$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
function showFinding(id){
  const f=findings.find(item=>item.id===id);if(!f)return;
  $('#detail-severity').className=`pill ${pillClass(f.severity)}`;
  $('#detail-severity').style.setProperty('--color',`var(--${colors[f.severity]})`);
  $('#detail-severity').textContent=f.severity.toUpperCase();
  $('#detail-title').textContent=f.title;
  $('#detail-category').textContent=`${f.category} · review candidate`;
  $('#detail-evidence').textContent=f.evidence;
  $('#detail-resource').textContent=`Sample source: ${f.resource}`;
  $('#detail-remediation').textContent=f.remediation;
  $('#finding-dialog').showModal();
}
document.addEventListener('click',event=>{
  const finding=event.target.closest('[data-finding]');if(finding)showFinding(Number(finding.dataset.finding));
  const go=event.target.closest('[data-go]');if(go)location.hash=go.dataset.go;
  const close=event.target.closest('[data-close]');if(close)close.closest('dialog').close();
});
window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
$('#search').addEventListener('input',renderFindings);
$('#severity').addEventListener('change',renderFindings);
$('#new-audit').addEventListener('click',()=>{$('#form-error').textContent='';$('#setup-dialog').showModal();});
$('#review-critical').addEventListener('click',()=>{$('#search').value='';$('#severity').value=findings.some(f=>f.severity==='Critical')?'Critical':'all';renderFindings();location.hash='findings';});
for(const id of ['about','avatar'])$(`#${id}`).addEventListener('click',()=>$('#about-dialog').showModal());
function exportReport(){
  const report={demo:true,notice:'Synthetic demo data. No target was contacted. All evidence is redacted.',target,selected_checks:selectedChecks,coverage:{attempted:25,scanned:22,limitations:['robots exclusion','size limit','timeout','No JavaScript execution or authenticated crawl']},findings};
  const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='gilbrt-demo-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);notify('Sample report exported. All values remain redacted.');
}
$('#export-top').addEventListener('click',exportReport);$('#export-results').addEventListener('click',exportReport);
$('#setup-form').addEventListener('submit',event=>{
  event.preventDefault();
  let url;
  try{url=new URL($('#target').value);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error();}catch{$('#form-error').textContent='Enter an HTTP or HTTPS URL without embedded credentials.';return;}
  const checks=all('input[name=checks]:checked').map(el=>el.value);
  if(!checks.length){$('#form-error').textContent='Select at least one check.';return;}
  $('#setup-dialog').close();
  startScan(url,checks);
});
function startScan(url,checks){
  let step=0;
  const stages=['Preparing scope','Reading robots.txt','Fetching documents','Inspecting scripts','Reviewing selected checks','Preparing report'];
  const logs=['Scope configured · exact origin','Sample robots rules loaded','12 sample documents processed','8 scripts + 2 source maps processed','Selected sample checks complete','Redacted report ready'];
  $('#scan-target').textContent=url.hostname;$('#scan-log').textContent='';$('#progress-fill').style.width='0%';$('#scan-percent').textContent='0%';$('#scan-stage').textContent=stages[0];$('#scan-dialog').showModal();
  scanTimer=setInterval(()=>{
    $('#scan-stage').textContent=stages[step];
    const entry=document.createElement('div');entry.textContent=`✓ ${logs[step]}`;$('#scan-log').append(entry);while($('#scan-log').children.length>4)$('#scan-log').firstElementChild.remove();
    const percent=Math.round((step+1)/stages.length*100);$('#progress-fill').style.width=`${percent}%`;$('#scan-percent').textContent=`${percent}%`;step++;
    if(step===stages.length){clearInterval(scanTimer);scanTimer=null;completionTimer=setTimeout(()=>{
      if(!$('#scan-dialog').open)return;
      $('#scan-dialog').close();target=url.origin;selectedChecks=checks;findings=samples.filter(f=>checks.includes(f.group));
      $('#target-name').textContent=url.host;$('#target-meta').textContent=`${url.protocol==='https:'?'HTTPS':'HTTP'} · PASSIVE AUDIT · SIMULATED SESSION`;
      $('#severity').value='all';$('#search').value='';render();location.hash='overview';navigate('overview');notify('Demo audit complete. Review your sample results.');
    },550);}
  },650);
}
function cancelScan(){if(scanTimer)clearInterval(scanTimer);if(completionTimer)clearTimeout(completionTimer);scanTimer=null;completionTimer=null;$('#scan-dialog').close();notify('Demo audit cancelled. Previous results retained.');}
$('#cancel-scan').addEventListener('click',cancelScan);
$('#scan-dialog').addEventListener('cancel',event=>{event.preventDefault();cancelScan();});
const resources=[['Document · demo-01','Scanned'],['JavaScript · demo-02','Scanned'],['Source map · demo-03','Scanned'],['Document · demo-23','Blocked by robots.txt'],['JavaScript · demo-24','Exceeded size limit'],['Document · demo-25','Request timeout']];
$('#resource-list').innerHTML=resources.map(([name,status])=>`<div class="resource-row"><strong>${safe(name)}</strong><span class="${status==='Scanned'?'mint-text':''}">${safe(status)}</span></div>`).join('');
render();navigate(location.hash.slice(1));
