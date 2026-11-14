import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request, createServer } from 'node:http';

async function fixture(t, env = {}) {
  const root = await mkdtemp(join(tmpdir(), 'ld-ui-'));
  await writeFile(join(root, 'index.html'), '<html>UI</html>');
  const child = spawn(process.execPath, ['deploy/server.mjs'], {
    env: { ...process.env, DIST: root, PORT: '0', HOST: '127.0.0.1', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(async () => {
    child.kill();
    await new Promise(resolve => child.once('exit', resolve));
    await rm(root, { recursive: true, force: true });
  });
  const address = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.stdout.once('data', data => resolve(String(data).match(/http:\/\/([^ ]+)/)[1]));
  });
  return { root, get: (path, headers) => new Promise((resolve, reject) => {
    request(`http://${address}`, { path, headers }, res => {
      res.resume();
      res.on('end', () => resolve(res));
    }).on('error', reject).end();
  }) };
}

test('malformed URL is rejected without killing the server', async t => {
  const { get } = await fixture(t);
  assert.equal((await get('/%E0%A4%A')).statusCode, 400);
  assert.equal((await get('/')).statusCode, 200);
});

test('ingress overwrites spoofed client identity with its TCP peer', async t => {
  let received;
  const api = createServer((req, res) => { received = req.headers; res.end('ok'); });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => api.close(resolve)));
  const { get } = await fixture(t, { API_PORT: String(api.address().port) });
  assert.equal((await get('/api/v1/auth/bootstrap', {
    'x-real-ip': '192.0.2.99', 'x-forwarded-for': '192.0.2.98', forwarded: 'for=192.0.2.97',
  })).statusCode, 200);
  assert.equal(received['x-real-ip'], '127.0.0.1');
  assert.equal(received['x-forwarded-for'], undefined);
  assert.equal(received.forwarded, undefined);
});

test('static files cannot escape into prefix siblings or external symlinks', async t => {
  const { root, get } = await fixture(t);
  const sibling = `${root}-outside`;
  await mkdir(sibling);
  t.after(() => rm(sibling, { recursive: true, force: true }));
  await writeFile(join(sibling, 'secret'), 'secret');
  await symlink(join(sibling, 'secret'), join(root, 'escape'));
  await writeFile(join(root, 'valid.js'), 'console.log(1)');
  assert.equal((await get(`/..%2f${sibling.split('/').pop()}/secret`)).statusCode, 403);
  assert.equal((await get('/escape')).statusCode, 403);
  assert.equal((await get('/valid.js')).statusCode, 200);
});

test('documents and assets have explicit browser security headers', async t => {
  const { root, get } = await fixture(t);
  await writeFile(join(root, 'asset.js'), 'console.log(1)');
  for (const path of ['/', '/asset.js']) {
    const response = await get(path);
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.match(response.headers['content-security-policy'], /default-src 'none'/);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.match(response.headers['content-security-policy'], /script-src 'self'/);
    assert.equal(response.headers['content-security-policy'].match(/connect-src ([^;]+)/)[1], "'self'");
  }
});

test('approved remote-signer relay origins extend connect-src and nothing else', async t => {
  const { get } = await fixture(t, { RELAY_ORIGINS: 'wss://relay.example wss://relay.example:443' });
  const response = await get('/');
  const connect = response.headers['content-security-policy'].match(/connect-src ([^;]+)/)[1];
  assert.equal(connect, "'self' wss://relay.example");
  assert.match(response.headers['content-security-policy'], /default-src 'none'/);
});

test('an unapproved relay origin fails at startup', async () => {
  for (const origin of ['https://relay.example', 'wss://relay.example/path', 'relay.example']) {
    const rejected = spawnSync(process.execPath, ['deploy/server.mjs'], {
      env: { ...process.env, DIST: '.', PORT: '0', RELAY_ORIGINS: origin },
      encoding: 'utf8',
    });
    assert.equal(rejected.status, 1, origin);
    assert.match(rejected.stderr, /wss:\/\/ origins/, origin);
  }
});
