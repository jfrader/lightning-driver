// Serves the built UI and proxies /api to the loopback API, preserving the browser's Host so the
// API's Origin and Host checks see the same origin the browser used.
import { readFile, stat } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { gzipSync } from 'node:zlib';

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
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.svg', '.json']);
const MIN_COMPRESS_BYTES = 1024;
/** Hashed build output never changes under the same name. */
const IMMUTABLE = /^\/assets\/.+-[A-Za-z0-9_-]+\.[a-z0-9]+$/;

/** Compressed bodies keyed by absolute path; a deploy restarts the unit, so the cache is per build. */
const compressed = new Map();

function headersFor(urlPath, path, length, encoding) {
  const headers = {
    'content-type': TYPES[extname(path)] ?? 'application/octet-stream',
    'content-length': length,
    'cache-control': IMMUTABLE.test(urlPath) ? 'public, max-age=31536000, immutable' : 'no-cache',
  };
  if (encoding) {
    headers['content-encoding'] = encoding;
    headers.vary = 'accept-encoding';
  }
  return headers;
}

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

async function send(req, res, urlPath, path) {
  const body = await readFile(path);
  const accepts = String(req.headers['accept-encoding'] ?? '');
  const type = extname(path);
  if (COMPRESSIBLE.has(type) && body.length >= MIN_COMPRESS_BYTES && /\bgzip\b/.test(accepts)) {
    let gzip = compressed.get(path);
    if (!gzip) {
      gzip = gzipSync(body, { level: 9 });
      compressed.set(path, gzip);
    }
    res.writeHead(200, headersFor(urlPath, path, gzip.length, 'gzip'));
    return req.method === 'HEAD' ? res.end() : res.end(gzip);
  }
  res.writeHead(200, headersFor(urlPath, path, body.length));
  return req.method === 'HEAD' ? res.end() : res.end(body);
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
    if (info.isFile()) return send(req, res, url.pathname, candidate);
  } catch {
    // fall through to the SPA entry
  }
  return send(req, res, '/index.html', join(DIST, 'index.html'));
}).listen(PORT, HOST, () => {
  console.log(`lightning-driver-ui on http://${HOST}:${PORT} (api ${API_HOST}:${API_PORT})`);
});
