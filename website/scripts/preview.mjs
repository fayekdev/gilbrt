import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import stats from '../api/stats.js';
const root = path.resolve(fileURLToPath(new URL('../public/', import.meta.url)));
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.sh': 'text/plain' };
http.createServer(async (req, res) => {
  if (new URL(req.url, 'http://localhost').pathname === '/api/stats') {
    res.status = value => { res.statusCode = value; return res; };
    res.json = value => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(value)); };
    return stats(req, res);
  }
  try {
    const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const filename = path.resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!filename.startsWith(root + path.sep) && filename !== path.join(root, 'index.html')) { res.writeHead(403); return res.end(); }
    const body = await readFile(filename);
    res.setHeader('Content-Type', `${types[path.extname(filename)] || 'application/octet-stream'}; charset=utf-8`);
    res.end(body);
  } catch { res.writeHead(404); res.end('Not found'); }
}).listen(4173, '127.0.0.1', () => console.log('gilbrt preview: http://127.0.0.1:4173'));
