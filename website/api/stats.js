const repository = 'fayekdev/gilbrt';
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=3600');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return res.status(405).json({ available: false });
  }
  try {
    const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'gilbrt-website', 'X-GitHub-Api-Version': '2022-11-28' };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const response = await fetch(`https://api.github.com/repos/${repository}`, { headers, signal: AbortSignal.timeout(6000) });
    if (!response.ok) return res.status(200).json({ available: false });
    const data = await response.json();
    return res.status(200).json({ available: true, stars: data.stargazers_count, forks: data.forks_count, issues: data.open_issues_count, updated: data.pushed_at, language: data.language, license: data.license?.spdx_id ?? null });
  } catch {
    return res.status(200).json({ available: false });
  }
}
