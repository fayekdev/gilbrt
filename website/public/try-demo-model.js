// Synthetic evidence only. This module performs no network or filesystem calls.
export const sampleFindings = [
  { id: 'demo-001', severity: 'Critical', title: 'Credential candidate in public source', category: 'API keys', resource: 'app.js · line 38', evidence: 'api_key: [REDACTED]', remediation: 'Review the candidate. If it is a real secret, revoke it and move credential handling to the server.' },
  { id: 'demo-002', severity: 'Warning', title: 'Missing Content-Security-Policy', category: 'Headers', resource: 'Document response', evidence: 'Content-Security-Policy: not present in sample', remediation: 'Define a Content Security Policy appropriate for the application and test it before enforcing it.' },
  { id: 'demo-003', severity: 'Warning', title: 'Token stored in browser storage', category: 'Browser code', resource: 'session.js · line 64', evidence: 'localStorage.setItem("token", [REDACTED])', remediation: 'Review whether browser-readable token storage is necessary and assess its exposure to script execution.' },
  { id: 'demo-004', severity: 'Warning', title: 'Missing X-Content-Type-Options', category: 'Headers', resource: 'Document response', evidence: 'X-Content-Type-Options: not present in sample', remediation: 'Set X-Content-Type-Options: nosniff and serve resources with accurate Content-Type headers.' },
  { id: 'demo-005', severity: 'Info', title: 'Client-side endpoint reference', category: 'Endpoints', resource: 'app.js · line 81', evidence: 'Reference to /api/account in sample source', remediation: 'Review endpoint authorization on the server. A public endpoint reference is not itself a vulnerability.' },
];

export function normalizeDemoTarget(value) {
  const input = value.trim();
  if (!input || input.length > 2000) throw new Error('Enter a website name or an HTTP(S) URL.');
  let url;
  try { url = new URL(/^[a-z][a-z\d+.-]*:/i.test(input) ? input : `https://${input}`); }
  catch { throw new Error('Enter a website name or an HTTP(S) URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname) throw new Error('Use an HTTP(S) website without embedded credentials.');
  return { display: url.host + (url.pathname === '/' ? '' : url.pathname), url: url.href };
}
export function createDemoReport(target) {
  return {
    demo: true,
    description: 'Synthetic sample report. No requests were sent to the target.',
    target: normalizeDemoTarget(target).url,
    coverage: { resources_checked: 12, resources_attempted: 12, source: 'Synthetic fixture' },
    findings: sampleFindings.map(finding => ({ ...finding })),
  };
}
export function parseDemoCommand(value) {
  const input = value.trim();
  if (input === 'clear') return { action: 'clear' };
  const tokens = [];
  const pattern = /\s*(?:"([^"]*)"|'([^']*)'|([^\s"']+))/gy;
  let position = 0;
  while (position < input.length) {
    pattern.lastIndex = position;
    const match = pattern.exec(input);
    if (!match) throw new Error('Close any quoted arguments and try again.');
    tokens.push(match[1] ?? match[2] ?? match[3]);
    position = pattern.lastIndex;
  }
  if (tokens[0] !== 'gilbrt') throw new Error('Demo commands: gilbrt, gilbrt --help, gilbrt --gui, or clear.');
  if (tokens.length === 2 && ['--help', '-h'].includes(tokens[1])) return { action: 'help' };
  if (tokens.length === 2 && tokens[1] === '--gui') return { action: 'gui' };
  let target;
  let format = 'text';
  for (let index = 1; index < tokens.length; index++) {
    const option = tokens[index];
    if (option === '--confirm-authorized') continue;
    if (option === '--url') {
      if (!tokens[index + 1] || tokens[index + 1].startsWith('--')) throw new Error('--url needs a website.');
      target = normalizeDemoTarget(tokens[++index]).url;
    } else if (option === '--format') {
      format = tokens[++index];
      if (!['text', 'json'].includes(format)) throw new Error('This demo supports --format text or --format json.');
    } else throw new Error(`Unsupported demo option: ${option}. Use gilbrt --help.`);
  }
  return { action: 'run', target, format };
}
