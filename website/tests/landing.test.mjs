import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readmeSections, topicMarkdown, safeReadmeUrl } from '../public/readme-renderer.js';
import handler from '../api/readme.js';

const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');

test('README topics use actual repository sections without splitting fenced headings', () => {
  const markdown = '## Options\n```sh\n## not a section\n```\n## Graphical interface\nGUI';
  assert.deepEqual(readmeSections(markdown).map(s => s.title), ['gilbrt', 'Options', 'Graphical interface']);
  assert.match(topicMarkdown(markdown, 'cli'), /## not a section/);
  assert.doesNotMatch(topicMarkdown(markdown, 'cli'), /GUI/);
  for (const topic of ['start', 'cli', 'gui', 'reports']) assert.ok(topicMarkdown(readme, topic).trim(), topic);
  assert.equal(topicMarkdown(readme, 'all'), readme);
});

test('README links reject active URL schemes and resolve repository links', () => {
  for (const url of ['javascript:alert(1)', 'data:text/html,<script>', 'vbscript:msgbox', 'file:///secret']) assert.equal(safeReadmeUrl(url), null);
  assert.equal(safeReadmeUrl('install.sh'), 'https://github.com/fayekdev/gilbrt/blob/HEAD/install.sh');
  assert.equal(safeReadmeUrl('https://example.com/docs'), 'https://example.com/docs');
});

async function request(mock, method = 'GET') {
  const original = globalThis.fetch;
  globalThis.fetch = mock;
  const response = { headers: {}, setHeader(key, value) { this.headers[key] = value; }, status(value) { this.code = value; return this; }, json(body) { this.body = body; return this; } };
  try { await handler({ method }, response); return response; }
  finally { globalThis.fetch = original; }
}

test('README endpoint fetches only its configured repository and returns Markdown', async () => {
  const response = await request(async (url, options) => {
    assert.equal(url, 'https://api.github.com/repos/fayekdev/gilbrt/readme');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Accept, 'application/vnd.github.raw+json');
    return new Response('# gilbrt\n## Options\nDocs');
  });
  assert.deepEqual(response.body, { available: true, markdown: '# gilbrt\n## Options\nDocs' });
  assert.match(response.headers['Cache-Control'], /s-maxage=300/);
});

test('README endpoint handles rate limiting, empty bodies, and network errors without leaking details', async () => {
  for (const mock of [async () => new Response('', { status: 403 }), async () => new Response('  '), async () => { throw new Error('private-token'); }]) {
    const response = await request(mock);
    assert.deepEqual(response.body, { available: false });
  }
});

test('README endpoint bounds actual streamed bytes even without Content-Length', async () => {
  const response = await request(async () => new Response('a'.repeat(200001)));
  assert.deepEqual(response.body, { available: false });
});

test('README endpoint rejects writes before an upstream request', async () => {
  let fetched = false;
  const response = await request(async () => { fetched = true; }, 'POST');
  assert.equal(fetched, false);
  assert.equal(response.code, 405);
});
