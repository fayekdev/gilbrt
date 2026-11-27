const repo = 'https://github.com/fayekdev/gilbrt';

export function wireTabs(tabs, activate) {
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(tab));
    tab.addEventListener('keydown', event => {
      let next;
      const vertical = tab.closest('[role=tablist]')?.getAttribute('aria-orientation') === 'vertical';
      if (vertical && event.key === 'ArrowDown') next = (index + 1) % tabs.length;
      if (vertical && event.key === 'ArrowUp') next = (index + tabs.length - 1) % tabs.length;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next === undefined) return;
      event.preventDefault();
      activate(tabs[next]);
      tabs[next].focus();
    });
  });
}
export function selectTab(tabs, selected) {
  tabs.forEach(tab => {
    tab.setAttribute('aria-selected', String(tab === selected));
    tab.tabIndex = tab === selected ? 0 : -1;
  });
}

function setupInstaller() {
  const tabs = [...document.querySelectorAll('[data-os]')];
  const code = document.querySelector('#install-code');
  if (!code) return;
  const note = document.querySelector('#install-note');
  const copy = document.querySelector('#copy-install');
  const status = document.querySelector('#copy-status');
  let revision = 0;
  function quote(value) { return `'${value.replaceAll("'", "'\\''")}'`; }
  function renderInstall(tab) {
    revision++;
    selectTab(tabs, tab);
    const selected = tab.dataset.os;
    document.querySelector('#install-content').setAttribute('aria-labelledby', tab.id);
    code.textContent = selected === 'windows'
      ? `git clone ${repo}.git\ncd gilbrt\npy -3 -m venv .venv\n.\\.venv\\Scripts\\python.exe -m pip install -e .\n.\\.venv\\Scripts\\gilbrt.exe`
      : `curl -fsSL ${quote(`${location.origin}/install.sh`)} -o /tmp/gilbrt-install.sh\nbash /tmp/gilbrt-install.sh --add-path\nexport PATH="$HOME/.local/bin:$PATH"\ngilbrt`;
    note.textContent = selected === 'macos'
      ? 'Requires Git and Python 3.10+. macOS execution has not been verified.'
      : selected === 'windows'
        ? 'PowerShell · requires Git and the Python launcher (py).'
        : 'Bash · installs for your current user.';
    copy.textContent = 'Copy';
    status.textContent = '';
  }
  wireTabs(tabs, renderInstall);
  copy.addEventListener('click', async () => {
    const copiedRevision = revision;
    try {
      await navigator.clipboard.writeText(code.textContent);
      if (revision !== copiedRevision) return;
      copy.textContent = 'Copied';
      status.textContent = 'Installation commands copied.';
    } catch {
      if (revision !== copiedRevision) return;
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = 'Commands selected. Press Control+C or Command+C to copy.';
      copy.textContent = 'Selected';
    }
  });
  renderInstall(tabs[0]);
}

async function loadStars() {
  const count = document.querySelector('#repo-stars');
  if (!count) return;
  const link = count.closest('a');
  try {
    const response = await fetch('/api/stats', { signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error('Unavailable');
    const data = await response.json();
    if (!data.available || !Number.isSafeInteger(data.stars) || data.stars < 0) throw new Error('Unavailable');
    count.textContent = new Intl.NumberFormat().format(data.stars);
    const label = `${data.stars} GitHub star${data.stars === 1 ? '' : 's'}`;
    link.setAttribute('aria-label', `gilbrt on GitHub, ${label}`);
    link.title = label;
  } catch {
    count.hidden = true;
    link.title = 'View repository on GitHub; star count unavailable';
  }
}
setupInstaller();
loadStars();
