// Serves the built UI and proxies /api to the loopback API, preserving the browser's Host so the
// API's Origin and Host checks see the same origin the browser used.
import { readFile, stat, realpath } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import { extname, join, resolve, relative, isAbsolute, sep } from 'node:path';
import { gzipSync } from 'node:zlib';

const DIST = await realpath(process.env.DIST ?? '/usr/local/share/lightning-driver/dist');
const API_HOST = process.env.API_HOST ?? '127.0.0.1';
const API_PORT = Number(process.env.API_PORT ?? 8080);
const PORT = Number(process.env.PORT ?? 4400);
const HOST = process.env.HOST ?? '127.0.0.1';

// NIP-46 remote signing opens a WebSocket to a relay the operator chooses. Only the origins named
// here may be reached; anything else stays blocked by `connect-src`.
function relayOrigins(value) {
  return (value ?? '')
    .split(/\s+/)
    .filter(Boolean)
    .map((candidate) => {
      let url;
      try {
        url = new URL(candidate);
      } catch {
        throw new Error(`RELAY_ORIGINS must list wss:// origins, got ${candidate}`);
      }
      if (url.protocol !== 'wss:' || url.pathname !== '/' || url.search || url.hash) {
        throw new Error(`RELAY_ORIGINS must list wss:// origins, got ${candidate}`);
      }
      return url.origin;
    });
}

const CONNECT_SRC = ["'self'", ...new Set(relayOrigins(process.env.RELAY_ORIGINS))].join(' ');
const CONTENT_SECURITY_POLICY = `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src ${CONNECT_SRC}; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;

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
    'x-content-type-options': 'nosniff',
    'content-security-policy': CONTENT_SECURITY_POLICY,
    'referrer-policy': 'no-referrer',
  };
  if (encoding) {
    headers['content-encoding'] = encoding;
    headers.vary = 'accept-encoding';
  }
  return headers;
}

function proxy(req, res) {
  // This ingress trusts the TCP peer only, never client-supplied forwarding headers.
  const headers = { ...req.headers, 'x-real-ip': req.socket.remoteAddress?.replace(/^::ffff:/, '') };
  delete headers.forwarded;
  delete headers['x-forwarded-for'];
  const upstream = request(
    { host: API_HOST, port: API_PORT, method: req.method, path: req.url, headers },
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
  path = await realpath(path);
  if (!contained(path)) return res.writeHead(403).end();
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

function contained(path) {
  const part = relative(DIST, path);
  return part !== '..' && !part.startsWith(`..${sep}`) && !isAbsolute(part);
}

async function handle(req, res) {
  let url;
  let pathname;
  try {
    url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    pathname = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }
  if (url.pathname.startsWith('/api/')) return proxy(req, res);
  const candidate = resolve(DIST, `.${sep}${pathname}`);
  if (!contained(candidate)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const info = await stat(candidate);
    if (info.isFile()) return await send(req, res, url.pathname, candidate);
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
    // fall through to the SPA entry
  }
  return await send(req, res, '/index.html', join(DIST, 'index.html'));
}

createServer((req, res) => {
  handle(req, res).catch(() => {
    if (res.headersSent) return res.destroy();
    res.writeHead(500).end();
  });
}).listen(PORT, HOST, function () {
  console.log(`lightning-driver-ui on http://${HOST}:${this.address().port} (api ${API_HOST}:${API_PORT})`);
});
