// 零依赖静态服务器：托管构建产物（dist/），并提供 /health 健康接口。

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WEB_ROOT = path.resolve(process.env.WEB_ROOT || path.join(ROOT_DIR, 'dist'));
const PORT = Number(process.env.PORT || 8080);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/health') {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ status: 'ok', service: 'offline-review', time: new Date().toISOString() }));
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === '/') pathname = '/index.html';
    const filePath = path.resolve(WEB_ROOT, '.' + pathname);
    if (filePath !== WEB_ROOT && !filePath.startsWith(WEB_ROOT + path.sep)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Forbidden');
      return;
    }
    const data = await readFile(filePath);
    res.writeHead(200, {
      'content-type': MIME[path.extname(filePath).toLowerCase()] ?? 'application/octet-stream',
      'cache-control': 'no-store',
    });
    if (req.method === 'HEAD') res.end();
    else res.end(data);
  } catch (err) {
    if (err?.code === 'ENOENT' || err?.code === 'EISDIR') {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
    } else {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Internal Server Error');
    }
  }
});

server.listen(PORT, () => {
  console.log(`静态页面服务已启动：http://0.0.0.0:${PORT}/（根目录 ${WEB_ROOT}）`);
});
