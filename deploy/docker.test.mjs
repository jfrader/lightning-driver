import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm, chmod, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import { setTimeout } from 'node:timers/promises';
import { createServer } from 'node:http';

test('Compose keeps the API private and defaults to only the hardened app container', () => {
  // Use Compose itself to parse YAML/interpolation; no hand-written YAML parser.
  const config = JSON.parse(execFileSync('docker', [
    'compose', '-f', 'deploy/docker/compose.yaml', '--profile', 'https', 'config', '--format', 'json',
  ], { encoding: 'utf8', env: { ...process.env, APP_UID: '1000', APP_GID: '1000' } }));
  const { app, caddy } = config.services;
  assert.deepEqual(Object.keys(config.services).sort(), ['app', 'caddy']);
  assert.equal(app.user, '1000:1000');
  assert.equal(app.restart, 'unless-stopped');
  assert.equal(app.read_only, true);
  assert.deepEqual(app.cap_drop, ['ALL']);
  assert.ok(app.security_opt.includes('no-new-privileges:true'));
  assert.ok(app.tmpfs.some((value) => value.startsWith('/tmp:')));
  assert.deepEqual(app.ports.map(({ host_ip, target, published }) => ({ host_ip, target, published })), [
    { host_ip: '127.0.0.1', target: 4400, published: '4400' },
  ]);
  assert.ok(app.volumes.some((mount) => mount.type === 'bind'
    && mount.source === resolve('deploy/docker/state') && mount.target === '/state' && !mount.read_only));
  assert.deepEqual(caddy.profiles, ['https']);
  assert.deepEqual(caddy.ports.map((port) => port.target).sort((a, b) => a - b), [80, 443]);
  for (const service of [app, caddy]) {
    assert.ok(!service.privileged);
    assert.ok(!service.network_mode);
    assert.ok(!(service.ports ?? []).some((port) => port.target === 8080));
  }
  const defaults = execFileSync('docker', ['compose', '-f', 'deploy/docker/compose.yaml', 'config', '--services'], {
    encoding: 'utf8', env: { ...process.env, COMPOSE_PROFILES: '' },
  });
  assert.equal(defaults.trim(), 'app');
});

test('localhost config matches loopback auth rules and keeps state paths relative', async () => {
  const config = await readFile('deploy/docker/config.localhost.toml', 'utf8');
  // Parse with the standard TOML parser rather than treating commented examples as config.
  const parsed = JSON.parse(execFileSync('python3', ['-c',
    'import json,sys,tomllib; print(json.dumps(tomllib.loads(sys.stdin.read())))',
  ], { input: config, encoding: 'utf8' }));
  assert.deepEqual(parsed.nodes, []);
  assert.deepEqual(parsed.api, {
    bind: '127.0.0.1:8080', public_origin: 'http://localhost:4400', rp_id: 'localhost',
    database: 'manager.sqlite', invoice_key_file: 'pending-invoice.key', allow_insecure_loopback: true,
  });
  const unit = await readFile('deploy/standalone/lightning-driver.service', 'utf8');
  for (const directive of [
    'ExecStart=/bin/bash /opt/lightning-driver/run.sh', 'User=lightning-driver',
    'StateDirectory=lightning-driver', 'StateDirectoryMode=0700',
    'ReadWritePaths=/var/lib/lightning-driver', 'ProtectSystem=strict',
    'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'UMask=0077',
  ]) assert.ok(unit.split('\n').includes(directive), directive);
});

test('healthcheck probes UI/API without creating sessions and rejects proxy/origin errors', async (t) => {
  const requests = [];
  let apiStatus = 404;
  let apiBody = { error: { code: 'not_found' } };
  const server = createServer((req, res) => {
    requests.push({ path: req.url, host: req.headers.host });
    res.writeHead(req.url === '/' ? 200 : apiStatus);
    res.end(req.url === '/' ? '<html></html>' : JSON.stringify(apiBody));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const check = async () => {
    const proc = spawn(process.execPath, ['deploy/docker/healthcheck.mjs'], {
      env: { ...process.env, PORT: String(server.address().port), LIGHTNING_HOST: 'manager.example.com' },
      stdio: 'ignore',
    });
    return (await once(proc, 'exit'))[0];
  };
  assert.equal(await check(), 0);
  assert.deepEqual(requests, ['/', '/api/v1'].map((path) => ({ path, host: 'manager.example.com' })));
  for (const status of [403, 502]) {
    apiStatus = status;
    assert.notEqual(await check(), 0);
  }
  apiStatus = 404;
  apiBody = { error: { code: 'wrong_service' } };
  assert.notEqual(await check(), 0);
});

async function supervisor(t, env = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'lightning-supervisor-'));
  const state = join(directory, 'state');
  const events = join(directory, 'events');
  await mkdir(state, { mode: 0o700 });
  await writeFile(join(directory, 'config.localhost.toml'), 'nodes = []\n');
  const child = `
const role = process.argv[1].endsWith('api-server') ? 'api' : 'ui';
const log = (event) => appendFileSync(process.env.EVENTS, JSON.stringify({role, event, pid: process.pid}) + '\\n');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { log(signal); process.exit(0); });
log('ready');
if (process.env.FAIL_ROLE === role) setTimeout(() => process.exit(Number(process.env.FAIL_CODE)), 100);
setInterval(() => {}, 1000);
`;
  await writeFile(join(directory, 'server.mjs'), `import { appendFileSync } from 'node:fs';\n${child}`);
  await writeFile(join(directory, 'api-server'), `#!/usr/bin/env node\nconst { appendFileSync } = require('node:fs');\n${child}`);
  await chmod(join(directory, 'api-server'), 0o755);
  const proc = spawn('bash', [resolve('deploy/run.sh')], {
    env: { ...process.env, APP_DIR: directory, STATE_DIR: state, EVENTS: events, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  proc.stderr.on('data', (value) => { stderr += value; });
  const exited = once(proc, 'exit');
  const readEvents = async () => {
    try { return (await readFile(events, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  t.after(async () => {
    if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL');
    for (const event of await readEvents()) {
      try { process.kill(event.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    await rm(directory, { recursive: true, force: true });
  });
  async function ready() {
    for (let attempt = 0; attempt < 200; attempt++) {
      if ((await readEvents()).filter((event) => event.event === 'ready').length === 2) return;
      await setTimeout(10);
    }
    assert.fail(`children did not start: ${stderr}`);
  }
  return { proc, exited, ready, readEvents, state, directory };
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`supervisor creates private config and forwards ${signal} to both children`, { timeout: 10000 }, async (t) => {
    const run = await supervisor(t);
    await run.ready();
    assert.equal(await readFile(join(run.state, 'config.toml'), 'utf8'), 'nodes = []\n');
    assert.equal((await stat(join(run.state, 'config.toml'))).mode & 0o777, 0o600);
    run.proc.kill(signal);
    assert.equal((await run.exited)[0], signal === 'SIGTERM' ? 143 : 130);
    assert.deepEqual((await run.readEvents()).filter((event) => event.event === signal).map((event) => event.role).sort(), ['api', 'ui']);
  });
}

for (const role of ['api', 'ui']) {
  for (const code of ['0', '7']) {
    test(`supervisor fails and stops sibling when ${role} exits ${code}`, { timeout: 10000 }, async (t) => {
      const run = await supervisor(t, { FAIL_ROLE: role, FAIL_CODE: code });
      assert.equal((await run.exited)[0], 1);
      const events = await run.readEvents();
      assert.ok(events.some((event) => event.role !== role && event.event === 'SIGTERM'));
    });
  }
}

test('supervisor preserves an existing config', { timeout: 10000 }, async (t) => {
  const run = await supervisor(t);
  await run.ready();
  run.proc.kill('SIGTERM');
  await run.exited;
  await writeFile(join(run.state, 'config.toml'), 'operator-config\n');
  const second = spawn('bash', [resolve('deploy/run.sh')], {
    env: { ...process.env, APP_DIR: run.directory, STATE_DIR: run.state, EVENTS: join(run.directory, 'events'), FAIL_ROLE: 'ui', FAIL_CODE: '1' },
    stdio: 'ignore',
  });
  t.after(() => { if (second.exitCode === null) second.kill('SIGKILL'); });
  assert.equal((await once(second, 'exit'))[0], 1);
  assert.equal(await readFile(join(run.state, 'config.toml'), 'utf8'), 'operator-config\n');
});
