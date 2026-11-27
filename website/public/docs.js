import { wireTabs, selectTab } from './app.js';
import { renderReadme, topicMarkdown } from './readme-renderer.js';

const tabs = [...document.querySelectorAll('[data-doc]')];
const panel = document.querySelector('#docs-content');
const status = document.querySelector('#docs-status');
const outline = document.querySelector('#docs-outline');
const location = document.querySelector('#docs-location');
const readingTime = document.querySelector('#docs-reading-time');
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
const narrowReader = matchMedia('(max-width: 700px)');
function orientTabs() { tabs[0].closest('[role=tablist]').setAttribute('aria-orientation', narrowReader.matches ? 'horizontal' : 'vertical'); }
orientTabs();
narrowReader.addEventListener('change', orientTabs);
let readme = '';
let selected = tabs[0];
let transition;
const paths = { start: 'quick-start', cli: 'command-line', gui: 'browser-interface', reports: 'reports', all: 'reference' };

function decorateCode() {
  panel.querySelectorAll('pre').forEach(pre => {
    const wrapper = document.createElement('div');
    wrapper.className = 'docs-code';
    const toolbar = document.createElement('div');
    toolbar.className = 'docs-code-toolbar';
    const language = document.createElement('span');
    language.textContent = pre.dataset.language || 'Code';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'docs-copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code example');
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(pre.textContent);
        if (!button.isConnected) return;
        button.textContent = 'Copied';
        button.setAttribute('aria-label', 'Code example copied');
      } catch {
        if (!button.isConnected) return;
        const range = document.createRange();
        range.selectNodeContents(pre);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = 'Selected';
        button.setAttribute('aria-label', 'Code selected; press Control+C or Command+C');
      }
    });
    toolbar.append(language, button);
    pre.replaceWith(wrapper);
    wrapper.append(toolbar, pre);
  });
}
function updateOutline() {
  outline.replaceChildren();
  const headings = [...panel.querySelectorAll('h2, h3, h4')];
  headings.forEach((heading, index) => {
    heading.id = `guide-${selected.dataset.doc}-${index}`;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = heading.textContent;
    button.addEventListener('click', () => {
      const top = panel.scrollTop + heading.getBoundingClientRect().top - panel.getBoundingClientRect().top - 24;
      panel.scrollTo({ top: Math.max(0, top), behavior: reducedMotion.matches ? 'instant' : 'smooth' });
    });
    outline.append(button);
  });
  outline.closest('nav').hidden = !headings.length;
}
function show(tab, animate = true) {
  selected = tab;
  selectTab(tabs, tab);
  panel.setAttribute('aria-labelledby', tab.id);
  location.textContent = paths[tab.dataset.doc];
  if (!readme) return;
  transition?.cancel();
  const content = topicMarkdown(readme, tab.dataset.doc);
  if (content) panel.replaceChildren(renderReadme(content));
  else {
    const message = document.createElement('p');
    message.textContent = 'This topic has moved. Open the Full README tab for the current documentation.';
    panel.replaceChildren(message);
  }
  const words = content.trim().split(/\s+/).filter(Boolean).length;
  readingTime.textContent = words ? `${Math.max(1, Math.ceil(words / 220))} min read` : '';
  decorateCode();
  updateOutline();
  panel.scrollTop = 0;
  if (animate && !reducedMotion.matches) {
    transition = panel.animate([{ opacity: .25, transform: 'translateY(7px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 220, easing: 'ease-out' });
  }
}
wireTabs(tabs, show);
reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) transition?.cancel(); });

async function loadReadme() {
  try {
    let markdown;
    let source;
    try {
      const response = await fetch('/api/readme', { signal: AbortSignal.timeout(7000) });
      if (!response.ok) throw new Error('Unavailable');
      const data = await response.json();
      if (!data.available || typeof data.markdown !== 'string' || !data.markdown.trim() || data.markdown.length > 200000) throw new Error('Unavailable');
      markdown = data.markdown;
      source = 'Source: repository README';
    } catch {
      const response = await fetch('/readme.md', { signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error('Unavailable');
      markdown = await response.text();
      if (!markdown.trim() || markdown.length > 200000) throw new Error('Unavailable');
      source = 'Source: bundled README · GitHub unavailable';
    }
    readme = markdown;
    status.textContent = source;
    show(selected, false);
  } catch {
    status.textContent = 'README unavailable. Use the GitHub link to read the documentation.';
    panel.textContent = 'Documentation could not be loaded.';
  } finally {
    panel.setAttribute('aria-busy', 'false');
  }
}
loadReadme();
