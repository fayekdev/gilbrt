import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const source = readFileSync(new URL('../gilbrt/gui_assets/app.js', import.meta.url), 'utf8');
// Load the application functions without registering browser listeners or booting.
const functions = source.slice(0, source.indexOf("document.addEventListener('click'"));
function app() {
  const nodes = new Map(), lists = new Map();
  function node(selector) {
    if (!nodes.has(selector)) nodes.set(selector, {
      value:'', textContent:'', disabled:false, checked:false, attributes:{},
      style:{setProperty(key,value) { this[key] = value; }},
      classList:{toggle() {}}, setAttribute(key,value) { this.attributes[key] = value; },
      close() { this.open = false; }, showModal() { this.open = true; }
    });
    return nodes.get(selector);
  }
  const fields = Object.fromEntries(Object.entries({max_pages:128,max_depth:4,max_resource_mb:16,
    rate_limit:0,ai_candidate_limit:256,ai_max_chunks:'',model:'',ollama_url:'http://127.0.0.1:11434',
    export_format:'json',exclude_domain:'production.example.com\n staging.example.com '})
    .map(([key,value]) => [key,{value:String(value)}]));
  fields.sitemaps = {checked:true}; fields.ignore_robots = {checked:false};
  for (const selector of ['#settings-form','#setup-form']) node(selector).elements = {namedItem:key => fields[key]};
  lists.set('#audit-checks input:checked',[{value:'passwords'}]);
  lists.set('#settings-checks input:checked',[{value:'passwords'}]);
  node('#authorization').value = '0'; node('#target').value = 'http://127.0.0.1:8765/';
  const context = vm.createContext({document:{querySelector:node,querySelectorAll:s => lists.get(s) || []},
    AbortSignal,performance,URL,TextEncoder,setTimeout:() => 1,clearTimeout() {},setInterval:() => 1,clearInterval() {}});
  vm.runInContext(functions,context);
  vm.runInContext("settings={exclude_domain:['production.example.com'],checks:['passwords']};",context);
  return {context,node,fields,run:code => vm.runInContext(code,context)};
}

test('per-audit options leave configured exclusions intact; settings can edit them',() => {
  const ui = app();
  const perRun = ui.run("readAuditOptions(document.querySelector('#setup-form'))");
  assert.equal(perRun.sitemaps,true); assert.equal(perRun.max_pages,128);
  assert.equal(Object.hasOwn(perRun,'exclude_domain'),false);
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run('readSettings().exclude_domain'))),
    ['production.example.com','staging.example.com']);
});
test('slider unlocks only at full value, never starts an audit by itself, and resets',() => {
  const ui = app();
  for (const value of ['0','50','99','100']) {
    ui.node('#authorization').value = value; ui.run('updateConfirmation()');
    assert.equal(ui.node('#start-audit').disabled,value !== '100');
    assert.equal(ui.node('#confirm-track').style['--confirmation'],`${value}%`);
    assert.equal(ui.node('#start-audit').hidden,value !== '100');
    assert.equal(ui.node('#authorization').hidden,value === '100');
  }
  ui.run('resetConfirmation()');
  assert.equal(ui.node('#authorization').value,'0');
  assert.equal(ui.node('#start-audit').disabled,true);
});
test('partial slider blocks submission before any request',async () => {
  const ui = app(); let requests = 0;
  ui.context.request = () => { requests++; };
  ui.run('api=request'); ui.node('#authorization').value = '99';
  await ui.run('startAudit({preventDefault(){}})');
  assert.equal(requests,0);
  assert.match(ui.node('#form-error').textContent,/Slide fully/);
});
test('explicit confirmation submits configured exclusions and new options, then relocks',async () => {
  const ui = app(); const requests = [];
  ui.context.request = async (path,payload) => { requests.push({path,payload}); return {job:{status:'running'}}; };
  ui.run('api=request; updateScan=()=>{}; schedulePoll=()=>{};');
  ui.node('#authorization').value = '100';
  await ui.run('startAudit({preventDefault(){}})');
  assert.equal(requests.length,1); assert.equal(requests[0].path,'/api/audit');
  assert.equal(requests[0].payload.authorized,true);
  assert.equal(requests[0].payload.settings.sitemaps,true);
  assert.deepEqual(JSON.parse(JSON.stringify(requests[0].payload.settings.exclude_domain)),['production.example.com']);
  assert.equal(ui.node('#authorization').value,'0'); assert.equal(ui.node('#start-audit').disabled,true);
});
test('failed submission requires a fresh confirmation',async () => {
  const ui = app(); ui.context.request = async () => { throw Error('Fixture failure'); };
  ui.run('api=request'); ui.node('#authorization').value = '100';
  await ui.run('startAudit({preventDefault(){}})');
  assert.equal(ui.node('#form-error').textContent,'Fixture failure');
  assert.equal(ui.node('#start-audit').disabled,true);
  assert.equal(ui.node('#authorization').disabled,false);
});
test('old running server gives a restart instruction before enabling incompatible controls',async () => {
  const ui = app(); const connections = [];
  ui.context.fetch = async () => ({ok:true,json:async () => ({settings:{max_pages:25}})});
  ui.context.connectionResult = (...args) => connections.push(args);
  ui.run('connection=connectionResult');
  await ui.run('initialize()');
  assert.equal(connections[0][0],false);
  assert.match(connections[0][1],/Ctrl\+C.*gilbrt --gui/);
});

test('clipboard copies the selected server export rather than locally revealed evidence',async () => {
  const ui = app(), copied = [], requests = [];
  ui.context.navigator = {clipboard:{writeText:async text => copied.push(text)}};
  ui.context.fetch = async (path,options) => {
    requests.push({path,options}); return {ok:true,text:async () => 'REDACTED REPORT'};
  };
  ui.run("token='session-token'; report={findings:[{evidence:'locally revealed value'}]};");
  ui.node('#export-format').value = 'ai';
  await ui.run('copyReport()');
  assert.deepEqual(copied,['REDACTED REPORT']);
  assert.equal(requests[0].path,'/api/export?format=ai');
  assert.equal(requests[0].options.headers['X-Gilbrt-Token'],'session-token');
  assert.equal(ui.node('#copy-report').disabled,false);
  assert.equal(ui.node('#export-error').textContent,'');
  assert.match(ui.node('#export-status').textContent,/copied to clipboard/);
});

test('failed export never writes the clipboard and keeps copy available for retry',async () => {
  const ui = app(); let writes = 0;
  ui.context.navigator = {clipboard:{writeText:async () => { writes++; }}};
  ui.context.fetch = async () => ({ok:false,json:async () => ({error:'No report available.'})});
  await ui.run('copyReport()');
  assert.equal(writes,0); assert.equal(ui.node('#export-error').textContent,'No report available.');
  assert.equal(ui.node('#copy-report').disabled,false);
});

test('clipboard denial and unavailable API give usable fallback messages',async () => {
  const ui = app();
  ui.context.navigator = {};
  await ui.run('copyReport()');
  assert.match(ui.node('#export-error').textContent,/Use Download/);
  ui.context.fetch = async () => ({ok:true,text:async () => 'redacted'});
  ui.context.navigator.clipboard = {writeText:async () => { const error=Error('Denied'); error.name='NotAllowedError'; throw error; }};
  await ui.run('copyReport()');
  assert.match(ui.node('#export-error').textContent,/permission was denied/);
  assert.equal(ui.node('#copy-report').disabled,false);
});
