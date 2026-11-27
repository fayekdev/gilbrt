const MAX_README_BYTES = 200000;
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=3600');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return res.status(405).json({ available: false });
  }
  try {
    const headers = { Accept: 'application/vnd.github.raw+json', 'User-Agent': 'gilbrt-website', 'X-GitHub-Api-Version': '2022-11-28' };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const response = await fetch('https://api.github.com/repos/fayekdev/gilbrt/readme', { headers, signal: AbortSignal.timeout(5000), redirect: 'error' });
    if (!response.ok || Number(response.headers.get('content-length')) > MAX_README_BYTES) {
      await response.body?.cancel();
      return res.status(200).json({ available: false });
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_README_BYTES) { await reader.cancel(); return res.status(200).json({ available: false }); }
      chunks.push(value);
    }
    const markdown = Buffer.concat(chunks).toString('utf8');
    if (!markdown.trim()) return res.status(200).json({ available: false });
    return res.status(200).json({ available: true, markdown });
  } catch {
    return res.status(200).json({ available: false });
  }
}
