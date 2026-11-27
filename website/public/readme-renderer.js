// Split only real H2 headings, never heading-like lines inside fenced code.
export function readmeSections(markdown) {
  const sections = [{ title: 'gilbrt', markdown: '' }];
  let fence = null;
  for (const line of markdown.replace(/\r\n/g, '\n').split('\n')) {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker) {
      if (!fence) fence = { char: marker[1][0], length: marker[1].length };
      else if (marker[1][0] === fence.char && marker[1].length >= fence.length) fence = null;
    }
    const heading = !fence && line.match(/^##\s+(.+?)\s*#*$/);
    if (heading) sections.push({ title: heading[1], markdown: '' });
    sections.at(-1).markdown += line + '\n';
  }
  return sections;
}

export function topicMarkdown(markdown, topic) {
  if (topic === 'all') return markdown;
  const patterns = {
    start: /^(Install and run|Bash command and limited hardware)$/i,
    cli: /^(Options|Choose what to search for)$/i,
    gui: /^Graphical interface$/i,
    reports: /^(Export reports for AI tools|Evidence, limitations and privacy)$/i,
  };
  return readmeSections(markdown).filter(section => patterns[topic]?.test(section.title))
    .map(section => section.markdown).join('\n');
}

export function safeReadmeUrl(raw) {
  try {
    const url = new URL(raw, 'https://github.com/fayekdev/gilbrt/blob/HEAD/README.md');
    return ['https:', 'http:'].includes(url.protocol) ? url.href : null;
  } catch { return null; }
}

// Build DOM nodes instead of interpreting README HTML. Fetched content never
// becomes script, event handlers, inline styles, or unsanitized innerHTML.
function inline(parent, value) {
  const tokens = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\([^\s)]+\))/g;
  let last = 0;
  for (const match of value.matchAll(tokens)) {
    parent.append(document.createTextNode(value.slice(last, match.index)));
    const token = match[0];
    let node;
    if (token.startsWith('`')) { node = document.createElement('code'); node.textContent = token.slice(1, -1); }
    else if (token.startsWith('**')) { node = document.createElement('strong'); node.textContent = token.slice(2, -2); }
    else {
      const [, label, href] = token.match(/^\[([^\]]+)\]\((.+)\)$/);
      const safe = safeReadmeUrl(href);
      node = document.createElement(safe ? 'a' : 'span');
      node.textContent = label;
      if (safe) node.href = safe;
    }
    parent.append(node);
    last = match.index + token.length;
  }
  parent.append(document.createTextNode(value.slice(last)));
}

export function renderReadme(markdown) {
  const fragment = document.createDocumentFragment();
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  for (let i = 0; i < lines.length;) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    const fence = line.match(/^\s*(`{3,}|~{3,})(.*)$/);
    if (fence) {
      const content = [];
      const close = new RegExp(`^\\s*${fence[1][0]}{${fence[1].length},}\\s*$`);
      i++;
      while (i < lines.length && !close.test(lines[i])) content.push(lines[i++]);
      if (i < lines.length) i++;
      const pre = document.createElement('pre');
      const language = fence[2].trim().toLowerCase();
      const languages = { bash: 'Bash', sh: 'Shell', shell: 'Shell', powershell: 'PowerShell', ps1: 'PowerShell', python: 'Python', json: 'JSON', text: 'Text', javascript: 'JavaScript', js: 'JavaScript' };
      pre.dataset.language = languages[language] || 'Code';
      const code = document.createElement('code');
      code.textContent = content.join('\n');
      pre.append(code);
      fragment.append(pre);
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.+?)\s*#*$/);
    if (heading) {
      const node = document.createElement(`h${Math.min(heading[1].length + 1, 6)}`);
      inline(node, heading[2]);
      fragment.append(node);
      i++;
      continue;
    }
    const list = line.match(/^\s*(?:([-*+])|\d+\.)\s+(.+)$/);
    if (list) {
      const node = document.createElement(list[1] ? 'ul' : 'ol');
      while (i < lines.length) {
        const item = lines[i].match(/^\s*(?:([-*+])|\d+\.)\s+(.+)$/);
        if (!item || Boolean(item[1]) !== Boolean(list[1])) break;
        const li = document.createElement('li');
        inline(li, item[2]);
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*[-*+]\s/.test(lines[i])) {
          li.append(document.createTextNode(' ')); inline(li, lines[i++].trim());
        }
        node.append(li);
      }
      fragment.append(node);
      continue;
    }
    const paragraph = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() && !/^\s*(?:#{1,6}\s|`{3,}|~{3,}|[-*+]\s|\d+\.\s)/.test(lines[i])) paragraph.push(lines[i++].trim());
    const node = document.createElement('p');
    inline(node, paragraph.join(' '));
    fragment.append(node);
  }
  return fragment;
}
