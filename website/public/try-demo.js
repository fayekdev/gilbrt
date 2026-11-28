import './gui-demo.js';
import { wireTabs, selectTab } from './app.js';
import { createDemoReport, normalizeDemoTarget, parseDemoCommand } from './try-demo-model.js';

const tabs = [...document.querySelectorAll('[data-demo-view]')];
const target = document.querySelector('#demo-target');
const run = document.querySelector('#demo-run');
const gui = document.querySelector('#actual-gui-demo');
const status = document.querySelector('#demo-run-status');
const output = document.querySelector('#demo-terminal-output');
const command = document.querySelector('#demo-command');
const commandRun = document.querySelector('#demo-command-run');
const cliStatus = document.querySelector('#demo-cli-status');
let report = createDemoReport(target.value);
let busy = false;
let runId = 0;
const help = `gilbrt — browser demo\n\nCommands\n  gilbrt                         Replay the sample audit\n  gilbrt --url <website>          Change the sample target label\n  gilbrt --format json            Print the sample JSON report\n  gilbrt --gui                    Open the GUI report\n  gilbrt --help                   Show this help\n  clear                          Clear the terminal\n\nThis demo uses synthetic findings. It does not run the Python CLI,\nexecute shell commands, or contact the target website.`;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function appendTerminal(text) {
  // Bound session history, including repeated JSON previews.
  output.textContent = (output.textContent + text + '\n').slice(-50000);
  output.scrollTop = output.scrollHeight;
}
function selectView(tab) {
  selectTab(tabs, tab);
  for (const candidate of tabs) document.querySelector(`#${candidate.getAttribute('aria-controls')}`).hidden = candidate !== tab;
}
wireTabs(tabs, selectView);
function renderReport() {
  gui.setReport(report).catch(() => { status.textContent = 'The GUI demo could not load. The CLI tab is still available.'; });
}
gui.addEventListener('demo-replay', () => replay(target.value));
gui.addEventListener('demo-exported', () => { status.textContent = 'Sample JSON report exported.'; });
function validateTarget(value) {
  try {
    const normalized = normalizeDemoTarget(value);
    target.setCustomValidity('');
    return normalized;
  } catch (error) {
    target.setCustomValidity(error.message);
    target.reportValidity();
    return null;
  }
}
target.addEventListener('input', () => target.setCustomValidity(''));
function setBusy(value) {
  busy = value;
  run.disabled = value;
  commandRun.disabled = value;
  gui.setBusy(value).catch(() => {});
  target.disabled = value;
  command.disabled = value;
  run.textContent = value ? 'Replaying demo…' : 'Run demo audit';
  document.querySelector('.try-gui').setAttribute('aria-busy', String(value));
}
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function replay(value, format = 'text') {
  if (busy) return;
  const normalized = validateTarget(value);
  if (!normalized) return;
  const currentRun = ++runId;
  setBusy(true);
  target.value = normalized.display;
  command.value = `gilbrt --url ${JSON.stringify(normalized.url)} --confirm-authorized${format === 'json' ? ' --format json' : ''}`;
  status.textContent = 'Replaying sample audit…';
  cliStatus.textContent = 'Replaying sample audit.';
  appendTerminal(`\n$ gilbrt --url ${JSON.stringify(normalized.url)} --confirm-authorized${format === 'json' ? ' --format json' : ''}\n[demo] No target requests will be made.`);
  const stages = ['Loading synthetic resources', 'Reviewing example source and headers', 'Preparing the sample report'];
  for (const stage of stages) {
    await pause(300);
    if (currentRun !== runId) return;
    status.textContent = `${stage}…`;
    gui.setBusy(true, `${stage}…`).catch(() => {});
    appendTerminal(`[demo] ${stage}`);
  }
  report = createDemoReport(normalized.url);
  renderReport();
  if (format === 'json') appendTerminal(JSON.stringify(report, null, 2));
  else {
    appendTerminal('\nSEVERITY  FINDING');
    for (const finding of report.findings) appendTerminal(`${finding.severity.padEnd(9)} ${finding.title}`);
    appendTerminal('\nSample complete: 5 findings · 12 synthetic resources\n1 Critical · 3 Warning · 1 Info\nEvidence redacted. Candidates require review.');
  }
  status.textContent = 'Sample audit complete · 12 resources checked';
  cliStatus.textContent = 'Sample audit complete. Five findings.';
  setBusy(false);
}
document.querySelector('#demo-target-form').addEventListener('submit', event => {
  event.preventDefault();
  replay(target.value);
});
document.querySelector('#demo-command-form').addEventListener('submit', event => {
  event.preventDefault();
  if (busy || !command.value.trim()) return;
  try {
    const parsed = parseDemoCommand(command.value);
    if (parsed.action === 'clear') { output.textContent = ''; command.value = ''; cliStatus.textContent = 'Terminal cleared.'; }
    else if (parsed.action === 'help') { appendTerminal(`\n$ ${command.value}\n${help}`); cliStatus.textContent = 'Demo help displayed.'; }
    else if (parsed.action === 'gui') { selectView(tabs[0]); cliStatus.textContent = 'GUI report opened.'; }
    else replay(parsed.target || target.value, parsed.format);
  } catch (error) {
    appendTerminal(`\n$ ${command.value}\n${error.message}`);
    cliStatus.textContent = error.message;
  }
});
document.querySelectorAll('[data-demo-command]').forEach(button => button.addEventListener('click', () => {
  command.value = button.dataset.demoCommand;
  command.focus();
}));
window.addEventListener('pagehide', () => { runId++; });
window.addEventListener('pageshow', event => { if (event.persisted && busy) { setBusy(false); status.textContent = 'Demo replay interrupted. Run it again to finish.'; } });
renderReport();
appendTerminal('gilbrt — interactive browser demo\nSynthetic fixture loaded for vulnerable-site.com.\nType a command below, or run the prefilled sample.\nUse gilbrt --help for supported commands.');
selectView(tabs[0]);
