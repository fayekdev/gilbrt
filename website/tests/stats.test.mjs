import test from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/stats.js';

async function request(mock, method = 'GET') {
  const original = globalThis.fetch;
  globalThis.fetch = mock;
  const response = { headers: {}, setHeader(key, value) { this.headers[key] = value; }, status(value) { this.code = value; return this; }, json(body) { this.body = body; return this; } };
  try { await handler({ method }, response); return response; }
  finally { globalThis.fetch = original; }
}
test('returns only public stats and caches the GitHub response', async () => {
  const response = await request(async () => ({ ok: true, json: async () => ({ stargazers_count: 12, forks_count: 3, open_issues_count: 2, pushed_at: '2026-11-22T00:00:00Z', language: 'Python', license: null, private: true, secret: 'never-export' }) }));
  assert.deepEqual(response.body, { available: true, stars: 12, forks: 3, issues: 2, updated: '2026-11-22T00:00:00Z', language: 'Python', license: null });
  assert.match(response.headers['Cache-Control'], /s-maxage=300/);
});
test('private repositories and rate limiting produce an unavailable state', async () => {
  for (const status of [404, 403, 429, 500]) {
    const response = await request(async () => ({ ok: false, status }));
    assert.equal(response.code, 200);
    assert.deepEqual(response.body, { available: false });
  }
});
test('network failures do not expose exception details', async () => {
  const response = await request(async () => { throw new Error('sensitive-token'); });
  assert.deepEqual(response.body, { available: false });
});
test('rejects writes without making upstream requests', async () => {
  const response = await request(async () => { throw new Error('should not run'); }, 'POST');
  assert.equal(response.code, 405);
  assert.equal(response.headers.Allow, 'GET, HEAD');
});
