// Serves the built UI and proxies /api to the loopback API, preserving the browser's Host so the
// API's Origin and Host checks see the same origin the browser used.
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { extname, join, normalize } from 'node:path';

const DIST = process.env.DIST ?? '/usr/local/share/lightning-driver/dist';
const API_HOST = process.env.API_HOST ?? '127.0.0.1';
const API_PORT = Number(process.env.API_PORT ?? 8080);
const PORT = Number(process.env.PORT ?? 4400);
const HOST = process.env.HOST ?? '127.0.0.1';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.json': 'application/json',
};

function proxy(req, res) {
  const upstream = request(
    { host: API_HOST, port: API_PORT, method: req.method, path: req.url, headers: req.headers },
    (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers);
      answer.pipe(res);
    },
  );
  upstream.on('error', () => {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('API unavailable');
  });
  req.pipe(upstream);
}

async function send(res, path) {
  const type = TYPES[extname(path)] ?? 'application/octet-stream';
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-cache' });
  createReadStream(path).pipe(res);
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (url.pathname.startsWith('/api/')) return proxy(req, res);
  const candidate = normalize(join(DIST, decodeURIComponent(url.pathname)));
  if (!candidate.startsWith(DIST)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const info = await stat(candidate);
    if (info.isFile()) return send(res, candidate);
  } catch {
    // fall through to the SPA entry
  }
  return send(res, join(DIST, 'index.html'));
}).listen(PORT, HOST, () => {
  console.log(`lightning-driver-ui on http://${HOST}:${PORT} (api ${API_HOST}:${API_PORT})`);
});
