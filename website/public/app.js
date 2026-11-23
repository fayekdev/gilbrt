const repo = 'https://github.com/fayekdev/gilbrt';
const tabs = [...document.querySelectorAll('[data-os]')];
const ai = document.querySelector('#with-ai');
const code = document.querySelector('#install-code');
const note = document.querySelector('#install-note');
const shell = document.querySelector('#shell-label');
const copy = document.querySelector('#copy-install');
let selected = 'linux';
// Use a shell-quoted current origin, including Vercel previews and custom domains.
function quote(value) { return `'${value.replaceAll("'", "'\\''")}'`; }
function renderInstall() {
  const windows = selected === 'windows';
  const mac = selected === 'macos';
  ai.disabled = mac;
  if (mac) ai.checked = false;
  const extra = ai.checked ? ' --with-ai' : '';
  tabs.forEach(tab => {
    const active = tab.dataset.os === selected;
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  document.querySelector('#install-content').setAttribute('aria-labelledby', `tab-${selected}`);
  shell.textContent = windows ? 'POWERSHELL' : 'BASH';
  code.textContent = windows
    ? `git clone ${repo}.git\ncd gilbrt\npy -3 -m venv .venv\n.\\.venv\\Scripts\\python.exe -m pip install -e .${ai.checked ? '\n.\\.venv\\Scripts\\python.exe scripts/install_small_ai.py' : ''}\n.\\.venv\\Scripts\\gilbrt.exe`
    : `curl -fsSL ${quote(`${location.origin}/install.sh`)} -o /tmp/gilbrt-install.sh\nbash /tmp/gilbrt-install.sh --add-path${extra}\nexport PATH="$HOME/.local/bin:$PATH"\ngilbrt`;
  note.textContent = mac
    ? 'Requires Git and Python 3.10+. Static checks use the Python CLI; the bundled AI runtime is not available for macOS. macOS execution has not been verified.'
    : windows
      ? `Requires Git and Python 3.10+ (with the py launcher). Run the executable directly; activation is optional.${ai.checked ? ' AI downloads about 469 MiB of model weights plus a CPU runner (x64/ARM64).' : ''}`
      : `Download the script, inspect it if desired, then run it. Requires Git, Python 3.10+ and venv. ${ai.checked ? 'AI downloads about 469 MiB of model weights plus a CPU runner (x64/ARM64); Linux runtime compatibility varies.' : 'Static checks do not require a model.'}`;
  copy.textContent = 'Copy';
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => { selected = tab.dataset.os; renderInstall(); });
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next === undefined) return;
    event.preventDefault(); selected = tabs[next].dataset.os; renderInstall(); tabs[next].focus();
  });
});
ai.addEventListener('change', renderInstall);
copy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(code.textContent);
    copy.textContent = 'Copied!';
    document.querySelector('#copy-status').textContent = 'Installation commands copied.';
  } catch {
    const range = document.createRange(); range.selectNodeContents(code);
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    document.querySelector('#copy-status').textContent = 'Copy unavailable. Commands selected; press Control+C or Command+C.';
    copy.textContent = 'Selected';
  }
});
renderInstall();
async function loadStats() {
  const status = document.querySelector('#stats-status');
  try {
    const response = await fetch('/api/stats', { signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error('unavailable');
    const data = await response.json();
    if (!data.available || !['stars', 'forks', 'issues'].every(key => Number.isInteger(data[key]) && data[key] >= 0)) throw new Error('unavailable');
    const format = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });
    document.querySelectorAll('[data-stat]').forEach(el => { el.textContent = format.format(data[el.dataset.stat]); });
    status.textContent = 'Live GitHub statistics · cached for up to 5 minutes';
  } catch {
    status.textContent = 'GitHub stats are unavailable. The repository may be private or temporarily unreachable.';
  }
}
loadStats();
if ('IntersectionObserver' in window) {
  document.documentElement.classList.add('js');
  const observer = new IntersectionObserver(entries => entries.forEach(entry => {
    if (entry.isIntersecting) { entry.target.classList.add('visible'); observer.unobserve(entry.target); }
  }), { threshold: 0.08 });
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}
