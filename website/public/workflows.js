import { wireTabs, selectTab } from './app.js';

const workflows = {
  release: {
    caption: 'Release check',
    title: 'Run against your staging site.',
    description: 'Check security headers, TLS, and credential candidates before promoting a release.',
    notes: ['Bounded to 25 resource attempts', 'Static source and header checks', 'Redacted HTML report'],
    command: 'gilbrt --url https://staging.your-domain.example --confirm-authorized --search headers,tls,api-keys,tokens,passwords,private-keys --max-pages 25 --output release-review.html --format html',
  },
  source: {
    caption: 'Source review',
    title: 'Check what the client receives.',
    description: 'Inspect fetched public source for credential candidates after changing frontend configuration.',
    notes: ['Passwords, API keys, tokens, and private keys', 'Candidates require human review', 'Redacted HTML report'],
    command: 'gilbrt --url https://staging.your-domain.example --confirm-authorized --search passwords,api-keys,tokens,private-keys --max-pages 25 --output source-review.html --format html',
  },
  handoff: {
    caption: 'Review handoff',
    title: 'Make findings easier to review.',
    description: 'Save a redacted report with coverage details for a teammate or your own issue-tracking workflow.',
    notes: ['JSON for further processing', 'Source references and coverage included', 'Sensitive values remain redacted'],
    command: 'gilbrt --url https://staging.your-domain.example --confirm-authorized --search headers,tls,passwords,api-keys,tokens,private-keys --max-pages 25 --output audit.json --format json',
  },
};
const tabs = [...document.querySelectorAll('[data-workflow]')];
const panel = document.querySelector('#workflow-panel');
const code = document.querySelector('#workflow-code');
const copy = document.querySelector('#copy-workflow');
const status = document.querySelector('#workflow-copy-status');
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
let revision = 0;
let transition;
function show(tab, animate = true) {
  const workflow = workflows[tab.dataset.workflow];
  revision++;
  transition?.cancel();
  selectTab(tabs, tab);
  panel.setAttribute('aria-labelledby', tab.id);
  document.querySelector('#workflow-caption').textContent = workflow.caption;
  document.querySelector('#workflow-title').textContent = workflow.title;
  document.querySelector('#workflow-description').textContent = workflow.description;
  document.querySelector('#workflow-notes').replaceChildren(...workflow.notes.map(text => {
    const li = document.createElement('li');
    li.textContent = text;
    return li;
  }));
  code.textContent = workflow.command;
  copy.textContent = 'Copy';
  status.textContent = '';
  if (animate && !reducedMotion.matches) {
    transition = panel.animate([{ opacity: .35, transform: 'translateY(6px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 240, easing: 'ease-out' });
  }
}
wireTabs(tabs, show);
copy.addEventListener('click', async () => {
  const copiedRevision = revision;
  try {
    await navigator.clipboard.writeText(code.textContent);
    if (copiedRevision !== revision) return;
    copy.textContent = 'Copied';
    status.textContent = 'Workflow command copied.';
  } catch {
    if (copiedRevision !== revision) return;
    const range = document.createRange();
    range.selectNodeContents(code);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    copy.textContent = 'Selected';
    status.textContent = 'Command selected. Press Control+C or Command+C to copy.';
  }
});
reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) transition?.cancel(); });
show(tabs[0], false);
