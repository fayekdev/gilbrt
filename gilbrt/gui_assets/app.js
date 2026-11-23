const $ = selector => document.querySelector(selector);
const all = selector => [...document.querySelectorAll(selector)];
const safe = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const names = {'passwords':'Passwords','api-keys':'API keys','tokens':'Tokens','private-keys':'Private keys','entropy':'High-entropy values','comments':'Comments','endpoints':'Endpoint references','headers':'Security headers','tls':'TLS configuration','breaches':'Breach catalogue','access-codes':'Access codes','connections':'Connection strings','browser-code':'Browser code','forms':'Forms'};
let token = '', settings = null, checks = [], models = [], report = null, job = null;
let pollTimer = null, toastTimer = null, lastTerminal = '', connected = false;
const severityColor = {Critical:'var(--red)',Warning:'var(--yellow)',Info:'var(--blue)'};
async function api(path, body) {
  const response = await fetch(path,{method:body===undefined?'GET':'POST',headers:{'X-Gilbrt-Token':token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const data = await response.json();
  if(!response.ok) throw Error(data.error || 'The local engine could not complete this request.');
  return data;
}
function notify(message){clearTimeout(toastTimer);$('#toast').textContent=message;$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,4500);}
function navigate(page){
  if(!['overview','findings','coverage','settings'].includes(page))page='overview';
  all('.page').forEach(el=>el.hidden=el.id!==`${page}-page`);
  all('[data-page]').forEach(el=>{el.classList.toggle('active',el.dataset.page===page);if(el.dataset.page===page)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
  $('#breadcrumb').textContent=page[0].toUpperCase()+page.slice(1);
  $('#page-title').innerHTML=`${{overview:'Audit overview',findings:'Your findings',coverage:'Audit coverage',settings:'Your settings'}[page]}<span>.</span>`;
  $('#page-subtitle').textContent={overview:'A clearer picture of your website’s exposure.',findings:'Look at the evidence. Decide what needs attention.',coverage:'Know what was scanned, and what was left unseen.',settings:'Set your scope. Choose your model. Make it yours.'}[page];
  document.title=`gilbrt — ${$('#breadcrumb').textContent}`;
  window.scrollTo(0,0);
}
function rows(findings){return findings.map(f=>`<button class="finding-row" data-finding="${f.index}"><span class="pill" style="--color:${severityColor[f.severity]||'var(--blue)'}">${safe(f.severity.toUpperCase())}</span><span><span class="finding-title">${safe(f.title)}</span><span class="finding-meta">${safe(f.url)}</span></span><span class="finding-category">${safe(f.category)}</span><span class="row-open" aria-hidden="true">›</span></button>`).join('');}
function indexedFindings(){return (report?.findings||[]).map((f,index)=>({...f,index}));}
function renderFindings(){
  const findings=indexedFindings(),query=$('#search').value.trim().toLowerCase(),severity=$('#severity').value;
  const filtered=findings.filter(f=>(severity==='all'||f.severity===severity)&&[f.title,f.category,f.evidence,f.url].join(' ').toLowerCase().includes(query));
  $('#results-count').textContent=`${filtered.length} of ${findings.length} findings · values redacted`;
  $('#all-findings').innerHTML=rows(filtered)||`<p class="empty">${report?'No matching findings. Try another search or severity.':'Start an authorized audit to see findings.'}</p>`;
}
function render(){
  const findings=indexedFindings(),meta=report?.metadata||{},inventory=meta.resource_inventory||[];
  const coverage=findings.filter(f=>f.category==='Coverage'),critical=findings.filter(f=>f.severity==='Critical'),warnings=findings.filter(f=>f.severity==='Warning');
  const attempted=meta.resources_attempted||0,scanned=meta.resources_scanned||0;
  const risk=$('.score-card .ring');
  const state=!report?['WAIT','mint',0]:critical.length?['HIGH','red',72]:warnings.length?['MED','blue',45]:['INFO','mint',15];
  risk.className=`ring ${state[1]}`;risk.style.setProperty('--value',state[2]);risk.querySelector('strong').textContent=state[0];risk.querySelector('div>span').textContent='PRIORITY';
  $('.score-card .score-copy').innerHTML=`<span class="pill ${state[1]}">${report?(critical.length?'ACTION NEEDED':warnings.length?'REVIEW NEEDED':'CHECK COVERAGE'):'READY WHEN YOU ARE'}</span><p>${report?(critical.length?'Review critical findings first.':'Read findings and coverage together.'):'Start your first authorized audit.'}</p><small>${report?`${critical.length} critical candidate${critical.length===1?'':'s'}`:'No requests made yet'}</small>`;
  $('.score-card .card-foot').innerHTML='<span>Severity indicates review priority</span><span>Not a security rating</span>';
  const coverageCard=all('.score-card')[1],percent=attempted?Math.round(scanned/attempted*100):null;
  coverageCard.querySelector('.ring').style.setProperty('--value',percent||0);
  coverageCard.querySelector('.ring strong').innerHTML=percent===null?'—':`${percent}<span>%</span>`;
  coverageCard.querySelector('.score-copy').innerHTML=`<span class="pill mint">${scanned} OF ${attempted} ATTEMPTED</span><p>${report?(coverage.length?'Review coverage gaps.':'Bounded to your selected scope.'):'Coverage appears after an audit.'}</p><small>${coverage.length} coverage observations</small>`;
  coverageCard.querySelector('.card-foot').innerHTML='<span>Attempted resources only</span><button data-go="coverage">View coverage</button>';
  $('#score-count').textContent=report?findings.length:'—';
  all('.score-card')[2].querySelector('.ring').style.setProperty('--value',report?100:0);
  all('.score-card')[2].querySelector('.card-foot').innerHTML='<span>Candidates, pending validation</span><button data-go="findings">View findings</button>';
  $('#nav-count').textContent=findings.length;
  ['Critical','Warning','Info'].forEach(level=>$(`#${level.toLowerCase()}-count`).textContent=findings.filter(f=>f.severity===level).length);
  $('#priority-list').innerHTML=rows(findings.slice(0,3))||`<p class="empty">${report?'No recorded findings. Review coverage before drawing conclusions.':'Your findings will appear here after an audit.'}</p>`;
  $('#insight-copy').textContent=!report?'Start with a website you own or have permission to audit. Your results will stay on this device unless you export them.':critical.length?`Review ${critical.length} critical candidate${critical.length===1?'':'s'} first. Check the recorded evidence and remediation before making changes.`:coverage.length?'This audit has coverage limitations. Read them before interpreting the remaining results.':findings.length?'Review the observations and their remediation. These findings require validation against your application.':'No findings were recorded in the scanned resources. This bounded audit does not establish security.';
  $('#review-critical').textContent=critical.length?'Review critical':'Review findings';
  const groupCounts=[findings.filter(f=>['Secret','Password','Connection'].includes(f.category)).length,findings.filter(f=>f.category==='Headers').length,findings.filter(f=>!['Secret','Password','Connection','Headers','Coverage'].includes(f.category)).length];
  all('.check-stat').forEach((el,index)=>{el.querySelector('strong').textContent=groupCounts[index];el.querySelector('i').style.width=`${findings.length?groupCounts[index]/findings.length*100:0}%`;});
  all('.check-stat')[2].querySelector('span').textContent='Other checks';
  const ai=meta.local_ai;
  $('.checks-note').innerHTML=`<span>Local AI</span><span>${!report?'Not started':ai?.enabled?`${safe(ai.backend)} · ${ai.chunks_analyzed} reviewed${ai.failed?' · errors':''}`:ai?.requested?'Requested · skipped':'Not requested'}</span>`;
  const origin=report?.session?.target_origin;
  $('#target-name').textContent=origin||'No completed audit';
  $('#target-meta').textContent=report?`${meta.active?'ACTIVE':'PASSIVE'} AUDIT · ${scanned} RESOURCES · ${meta.robots_respected?'ROBOTS RESPECTED':'ROBOTS OVERRIDE'}`:'START AN AUTHORIZED AUDIT';
  $('#target-status').innerHTML=`<i></i> ${job&&['running','cancelling'].includes(job.status)?'Audit running':report?'Audit complete':'Ready to audit'}`;
  const stats=$('.coverage-stats');
  stats.innerHTML=[[scanned,'Scanned'],[attempted,'Attempted'],[meta.max_pages??'—','Resource cap'],[coverage.length,'Coverage notes']].map(([value,label])=>`<div><strong>${value}</strong><span>${label}</span></div>`).join('');
  $('.coverage-content .panel-heading .pill').textContent=`${scanned} / ${attempted} ATTEMPTED`;
  $('.coverage-warning').innerHTML=`<strong>${report?'Keep the boundaries in mind.':'No coverage data yet.'}</strong><p>${report?`This passive audit does not execute JavaScript or crawl authenticated pages. Depth ${meta.max_depth}, resource limit ${meta.max_pages}, per-resource cap ${meta.max_resource_mb} MiB. ${meta.hibp_queried?'HIBP catalogue queried.':'HIBP catalogue not queried.'} Coverage percentage describes attempted resources, not the whole website.`:'Start an authorized audit. There is no sample data in this interface.'}</p>`;
  $('#resource-list').innerHTML=inventory.map(item=>`<div class="resource-row"><strong>${safe(item.resource)}</strong><span>${safe(item.kind)} · HTTP ${item.status} · ${(item.bytes/1024).toFixed(1)} KiB</span></div>`).join('')+coverage.map(f=>`<div class="coverage-note"><strong>${safe(f.title)}</strong><p>${safe(f.evidence)}</p><p>${safe(f.remediation)}</p></div>`).join('');
  $('#elapsed').textContent=report?`${Number(report.session.elapsed).toFixed(1)}s TOTAL`:'NO SESSION';
  for(const id of ['export-top','export-results'])$(`#${id}`).disabled=!report;
  renderActivity();renderFindings();
}
function renderActivity(){
  const events=job?.events||[];
  $('#activity-events').innerHTML=events.length?events.slice(-6).reverse().map(event=>`<div><span>${Number(event.elapsed).toFixed(1)}s</span><strong>${safe(event.stage)}</strong>${event.resource?`<small>${safe(event.resource)}</small>`:''}</div>`).join(''):'<p>No audit yet. Start an authorized audit to see activity.</p>';
}
function showFinding(index){
  const f=report?.findings[index];if(!f)return;
  $('#detail-severity').className='pill';$('#detail-severity').style.setProperty('--color',severityColor[f.severity]);$('#detail-severity').textContent=f.severity.toUpperCase();
  $('#detail-title').textContent=f.title;$('#detail-category').textContent=`${f.category} · review candidate`;
  $('#detail-evidence').textContent=f.evidence;$('#detail-resource').textContent=f.url;$('#detail-remediation').textContent=f.remediation;
  $('#finding-dialog').showModal();
}
function renderChecks(container,selected){$(container).innerHTML=checks.map(check=>`<label><input type="checkbox" value="${safe(check)}" ${selected.includes(check)?'checked':''}> ${safe(names[check]||check)}</label>`).join('');}
function setModelOptions(selector,value){
  const list=[...models];if(value&&!list.some(m=>m.id===value))list.push({id:value,name:`${value} · unavailable`});
  $(selector).innerHTML=list.map(model=>`<option value="${safe(model.id)}" ${model.id===value?'selected':''}>${safe(model.name)}</option>`).join('');
}
function fillSettings(){
  const form=$('#settings-form');
  for(const [name,value]of Object.entries(settings)){const field=form.elements.namedItem(name);if(!field)continue;if(field.type==='checkbox')field.checked=value;else field.value=value??'';}
  renderChecks('#settings-checks',settings.checks);setModelOptions('#settings-model',settings.model);$('#settings-error').textContent='';
  $('#export-results').textContent=`Export ${settings.export_format==='ai'?'AI Markdown':settings.export_format.toUpperCase()}`;
}
async function refreshModels(){
  const button=$('#refresh-models');button.disabled=true;$('#model-status').textContent='Checking installed local models…';
  const selected=$('#settings-model').value;
  try{
    const data=await api(`/api/models?url=${encodeURIComponent($('#ollama-url').value)}`);
    models=data.choices;setModelOptions('#settings-model',selected);setModelOptions('#audit-model',$('#audit-model').value||settings.model);
    $('#model-status').textContent=`${data.status}${data.available_memory_bytes?` Available RAM: ${(data.available_memory_bytes/1024**3).toFixed(1)} GiB.`:''}`;
    $('#model-catalogue').innerHTML=data.catalogue.map(model=>`<div><span>${safe(model.id)}</span><small>~${safe(model.download)} · ${model.ram_gib} GiB available RAM estimate</small></div>`).join('');
  }catch(error){$('#model-status').textContent=error.message;}finally{button.disabled=false;}
}
function readSettings(){
  const form=$('#settings-form'),result={...settings};
  for(const key of ['max_pages','max_depth','max_resource_mb','rate_limit','ai_candidate_limit'])result[key]=Number(form.elements.namedItem(key).value);
  const budget=form.elements.namedItem('ai_max_chunks').value;result.ai_max_chunks=budget===''?null:Number(budget);
  for(const key of ['model','ollama_url','export_format'])result[key]=form.elements.namedItem(key).value;
  result.ignore_robots=form.elements.namedItem('ignore_robots').checked;result.checks=all('#settings-checks input:checked').map(el=>el.value);return result;
}
async function saveSettings(event){
  event.preventDefault();$('#settings-error').textContent='';const button=$('#settings-form button[type=submit]');button.disabled=true;
  try{const result=await api('/api/settings',readSettings());settings=result.settings;fillSettings();notify('Settings saved for future audits.');}catch(error){$('#settings-error').textContent=error.message;}finally{button.disabled=false;}
}
function openSetup(){
  if(!connected)return notify('The local engine is unavailable. Reload after restarting gilbrt --gui.');
  if(job&&['running','cancelling'].includes(job.status)){updateScan();$('#scan-dialog').showModal();return;}
  renderChecks('#audit-checks',settings.checks);setModelOptions('#audit-model',settings.model);$('#authorization').checked=false;
  $('#form-error').textContent='';$('#audit-config-summary').textContent=`${settings.max_pages} resources · depth ${settings.max_depth} · ${settings.rate_limit}s delay · ${settings.max_resource_mb} MiB per resource. Change defaults in Settings.`;
  $('#setup-dialog').showModal();
}
async function startAudit(event){
  event.preventDefault();const button=$('#start-audit');button.disabled=true;$('#form-error').textContent='';
  try{
    const options={...settings,model:$('#audit-model').value,checks:all('#audit-checks input:checked').map(el=>el.value)};
    const data=await api('/api/audit',{target:$('#target').value,authorized:$('#authorization').checked,settings:options,include_urls:$('#include-urls').value.split('\n').map(x=>x.trim()).filter(Boolean)});
    job=data.job;$('#setup-dialog').close();updateScan();$('#scan-dialog').showModal();render();schedulePoll();
  }catch(error){$('#form-error').textContent=error.message;}finally{button.disabled=false;}
}
function updateScan(){
  if(!job)return;
  try{$('#scan-target').textContent=new URL(job.target).origin;}catch{$('#scan-target').textContent='Authorized scope';}
  $('#scan-stage').textContent=job.stage;$('#scan-percent').textContent=`${job.resources_scanned} scanned`;
  $('#scan-log').innerHTML=(job.events||[]).slice(-4).map(event=>`<div>${Number(event.elapsed).toFixed(1)}s · ${safe(event.stage)}${event.batch?` · batch ${event.batch}`:''}</div>`).join('');
  $('#cancel-scan').disabled=job.status==='cancelling';$('#cancel-scan').textContent=job.status==='cancelling'?'Stopping…':'Cancel audit';
}
function schedulePoll(delay=650){clearTimeout(pollTimer);pollTimer=setTimeout(poll,delay);}
async function poll(){
  try{
    const data=await api('/api/state');connected=true;job=data.job;report=data.report;
    if(job&&['running','cancelling'].includes(job.status)){updateScan();renderActivity();$('#target-status').innerHTML='<i></i> Audit running';schedulePoll();return;}
    if($('#scan-dialog').open)$('#scan-dialog').close();
    const terminal=job?`${job.id}:${job.status}`:'';
    if(terminal&&terminal!==lastTerminal){lastTerminal=terminal;render();if(job.status==='complete'){location.hash='overview';notify(`Audit complete. ${report.findings.length} observations recorded.`);}else notify(job.error||'Audit cancelled. Previous completed results retained.');}
  }catch(error){connected=false;$('#scan-stage').textContent='Connection lost. Waiting for the local engine…';$('#cancel-scan').disabled=false;notify(error.message||'Connection to the local engine was lost.');schedulePoll(3000);}
}
async function cancelAudit(){
  if(!job||!['running','cancelling'].includes(job.status))return;
  try{const data=await api('/api/cancel',{});job=data.job;updateScan();schedulePoll();}catch(error){notify(error.message);}
}
async function exportReport(){
  if(!report)return;try{
    const fmt=settings.export_format,response=await fetch(`/api/export?format=${fmt}`,{headers:{'X-Gilbrt-Token':token}});
    if(!response.ok){const data=await response.json();throw Error(data.error);}
    const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`gilbrt-report.${fmt==='ai'?'md':fmt}`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);notify('Redacted report exported.');
  }catch(error){notify(error.message);}
}
document.addEventListener('click',event=>{
  const finding=event.target.closest('[data-finding]');if(finding)showFinding(Number(finding.dataset.finding));
  const go=event.target.closest('[data-go]');if(go)location.hash=go.dataset.go;
  const close=event.target.closest('[data-close]');if(close)close.closest('dialog').close();
});
window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
$('#search').addEventListener('input',renderFindings);$('#severity').addEventListener('change',renderFindings);
$('#new-audit').addEventListener('click',openSetup);$('#setup-form').addEventListener('submit',startAudit);
$('#settings-form').addEventListener('submit',saveSettings);$('#refresh-models').addEventListener('click',refreshModels);
$('#cancel-scan').addEventListener('click',cancelAudit);$('#scan-dialog').addEventListener('cancel',event=>{event.preventDefault();cancelAudit();});
$('#review-critical').addEventListener('click',()=>{$('#search').value='';$('#severity').value=report?.findings.some(f=>f.severity==='Critical')?'Critical':'all';renderFindings();location.hash='findings';});
for(const id of ['about','avatar'])$(`#${id}`).addEventListener('click',()=>$('#about-dialog').showModal());
for(const id of ['export-top','export-results'])$(`#${id}`).addEventListener('click',exportReport);
$('#reset-settings').addEventListener('click',()=>{
  const form=$('#settings-form');for(const[name,value]of Object.entries({max_pages:25,max_depth:2,max_resource_mb:16,rate_limit:1,ollama_url:'http://127.0.0.1:11434',ai_max_chunks:'',ai_candidate_limit:256,export_format:'json',model:''}))form.elements.namedItem(name).value=value;
  form.elements.namedItem('ignore_robots').checked=false;renderChecks('#settings-checks',checks);notify('Defaults restored in the form. Save to apply.');
});
async function initialize(){
  $('#new-audit').disabled=true;models=[{id:'',name:'Static checks only'}];render();navigate(location.hash.slice(1));
  try{
    const response=await fetch('/api/bootstrap');if(!response.ok)throw Error('Unable to connect to the local engine.');const data=await response.json();
    token=data.token;settings=data.settings;checks=data.checks;job=data.job;report=data.report;connected=true;
    fillSettings();render();$('#new-audit').disabled=false;
    $('#hibp-status').textContent=data.hibp_available?'HIBP_API_KEY is available from the server environment. Breach checks use the HIBP catalogue.':'Breach catalogue checks require HIBP_API_KEY in the environment used to launch gilbrt. No key is stored in GUI settings.';
    await refreshModels();
    if(job&&['running','cancelling'].includes(job.status)){updateScan();$('#scan-dialog').showModal();schedulePoll();}else lastTerminal=job?`${job.id}:${job.status}`:'';
  }catch(error){$('#page-subtitle').textContent='Local engine unavailable. Start gilbrt --gui and reload this page.';notify(error.message);}
}
initialize();
