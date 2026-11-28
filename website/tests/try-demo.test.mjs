import test from 'node:test';
import assert from 'node:assert/strict';
import { createDemoReport, normalizeDemoTarget, parseDemoCommand } from '../public/try-demo-model.js';

test('demo target defaults normalize without making a request', () => {
  assert.deepEqual(normalizeDemoTarget('vulnerable-site.com'), { display: 'vulnerable-site.com', url: 'https://vulnerable-site.com/' });
  assert.equal(normalizeDemoTarget('http://example.test/path').url, 'http://example.test/path');
  for (const target of ['', 'https://', 'javascript:alert(1)', 'file:///secret', 'https://user:password@example.test']) assert.throws(() => normalizeDemoTarget(target));
});

test('sample reports explicitly identify synthetic coverage and contain consistent findings', () => {
  const report = createDemoReport('vulnerable-site.com');
  assert.equal(report.demo, true);
  assert.equal(report.target, 'https://vulnerable-site.com/');
  assert.equal(report.coverage.resources_checked, 12);
  assert.deepEqual(report.findings.map(f => f.severity), ['Critical', 'Warning', 'Warning', 'Warning', 'Info']);
  assert.ok(report.findings.every(f => f.evidence && f.remediation));
  report.findings[0].title = 'changed';
  assert.notEqual(createDemoReport('example.test').findings[0].title, 'changed');
});

test('CLI demo parses supported commands and quoted targets without executing a shell', () => {
  assert.deepEqual(parseDemoCommand('gilbrt --help'), { action: 'help' });
  assert.deepEqual(parseDemoCommand('gilbrt --gui'), { action: 'gui' });
  assert.deepEqual(parseDemoCommand('clear'), { action: 'clear' });
  assert.deepEqual(parseDemoCommand('gilbrt --url "https://example.test/path" --confirm-authorized --format json'), { action: 'run', target: 'https://example.test/path', format: 'json' });
  assert.deepEqual(parseDemoCommand('gilbrt'), { action: 'run', target: undefined, format: 'text' });
});

test('CLI demo rejects malformed, unsupported, and shell-like commands', () => {
  for (const command of ['curl https://example.test', 'gilbrt --url', 'gilbrt --url --format json', 'gilbrt --url "example.test', 'gilbrt --format xml', 'gilbrt --active', 'gilbrt && whoami', 'gilbrt ; whoami', 'gilbrt --url javascript:alert(1)']) assert.throws(() => parseDemoCommand(command), command);
});
