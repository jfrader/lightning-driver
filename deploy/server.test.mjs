import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ld-ui-'));
  await writeFile(join(root, 'index.html'), '<html>UI</html>');
  const child = spawn(process.execPath, ['deploy/server.mjs'], {
    env: { ...process.env, DIST: root, PORT: '0', HOST: '127.0.0.1' },
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
  return { root, get: path => new Promise((resolve, reject) => {
    request(`http://${address}`, { path }, res => {
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
