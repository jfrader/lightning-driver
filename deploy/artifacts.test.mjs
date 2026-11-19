import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, readFile, chmod } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('artifact verification fails closed for tampering, extra files and untrusted metadata', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ld-artifacts-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const ui = join(root, 'ui');
  const binary = join(root, 'api');
  const path = join(root, 'manifest.json');
  await mkdir(ui);
  await writeFile(join(ui, 'index.html'), 'ui');
  await writeFile(binary, 'api');
  const manifest = JSON.stringify({ version: 1,
    ui: { repository: 'https://github.com/jfrader/lightning-driver-ui', revision: 'a'.repeat(40), files: { 'index.html': sha('ui') } },
    api: { repository: 'https://github.com/jfrader/lightning-driver', revision: 'b'.repeat(40), sha256: sha('api') },
  });
  await writeFile(path, manifest);
  const verify = (digest = sha(manifest)) => spawnSync(process.execPath, ['deploy/verify-artifacts.mjs', path, digest, ui, binary]);
  assert.equal(verify().status, 0);
  assert.equal(verify('0'.repeat(64)).status, 1);
  await writeFile(binary, 'tampered');
  assert.equal(verify().status, 1);
  await writeFile(binary, 'api');
  await writeFile(join(ui, 'index.html'), 'tampered');
  assert.equal(verify().status, 1);
  await writeFile(join(ui, 'index.html'), 'ui');
  await writeFile(join(ui, 'extra.js'), 'extra');
  assert.equal(verify().status, 1);
  await rm(join(ui, 'extra.js'));
  await symlink(binary, join(ui, 'extra.js'));
  assert.equal(verify().status, 1);
  const installer = await readFile('deploy/install.sh', 'utf8');
  const readme = await readFile('README.md', 'utf8');
  // The installer never builds as root; the documented build step requires the lockfile.
  assert.match(readme, /cargo build --locked --release -p lightning-driver-api/);
  assert.match(installer, /never builds as root/);
  // A recording cargo stub proves the missing-binary path rejects without ever invoking a build.
  const bin = join(root, 'bin');
  const marker = join(root, 'cargo-called');
  await mkdir(bin);
  const stub = join(bin, 'cargo');
  await writeFile(stub, `#!/bin/sh\ntouch ${marker}\nexit 0\n`);
  await chmod(stub, 0o755);
  const rejection = spawnSync('bash', ['deploy/install.sh', '--ui-dist', ui], {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  assert.equal(rejection.status, 1);
  assert.match(String(rejection.stderr), /pass --binary/);
  assert.equal(existsSync(marker), false);
  const withoutManifest = spawnSync('bash', ['deploy/install.sh', '--ui-dist', ui, '--binary', binary]);
  assert.equal(withoutManifest.status, 1);
  assert.match(String(withoutManifest.stderr), /trusted --artifact-manifest/);
});
