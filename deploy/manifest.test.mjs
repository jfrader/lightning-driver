import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { digest } from './artifact-manifest.mjs';

const UI = 'a'.repeat(40);
const API = 'b'.repeat(40);

async function fixtures(t) {
  const root = await mkdtemp(join(tmpdir(), 'ld-manifest-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const ui = join(root, 'ui');
  const binary = join(root, 'api');
  const manifest = join(root, 'manifest.json');
  await mkdir(ui);
  await writeFile(join(ui, 'index.html'), 'ui');
  await writeFile(join(ui, 'asset.js'), 'asset');
  await writeFile(binary, 'api');
  return { root, ui, binary, manifest };
}

function generate({ ui, binary, manifest }) {
  return spawnSync(process.execPath, [
    'deploy/manifest.mjs',
    '--ui-dist', ui,
    '--ui-revision', UI,
    ...(binary ? ['--binary', binary, '--api-revision', API] : []),
    '--out', manifest,
  ]);
}

function verify({ ui, binary, manifest }, trusted) {
  return spawnSync(process.execPath, ['deploy/verify-artifacts.mjs', manifest, trusted, ui, binary]);
}

test('a generated manifest verifies, and every deviation fails closed', async t => {
  const files = await fixtures(t);
  const generated = generate(files);
  assert.equal(generated.status, 0, String(generated.stderr));
  const trusted = String(generated.stdout).trim();
  assert.match(trusted, /^[a-f0-9]{64}$/);
  assert.equal(verify(files, trusted).status, 0);

  const body = JSON.parse(await readFile(files.manifest, 'utf8'));
  assert.equal(body.version, 1);
  assert.deepEqual(Object.keys(body.ui.files).sort(), ['asset.js', 'index.html']);
  assert.equal(body.ui.revision, UI);
  assert.equal(body.api.revision, API);

  await writeFile(join(files.ui, 'asset.js'), 'tampered');
  assert.equal(verify(files, trusted).status, 1);
  await writeFile(join(files.ui, 'asset.js'), 'asset');

  await writeFile(join(files.ui, 'extra.js'), 'extra');
  assert.equal(verify(files, trusted).status, 1);
  await rm(join(files.ui, 'extra.js'));

  await symlink(files.binary, join(files.ui, 'extra.js'));
  assert.equal(verify(files, trusted).status, 1);
  await rm(join(files.ui, 'extra.js'));

  assert.equal(verify(files, digest(await readFile(files.manifest))).status, 0);
  assert.equal(verify(files, '0'.repeat(64)).status, 1);
});

test('the generator refuses an incomplete input', async t => {
  const files = await fixtures(t);
  const missingRevision = spawnSync(process.execPath, ['deploy/manifest.mjs', '--ui-dist', files.ui, '--out', files.manifest]);
  assert.equal(missingRevision.status, 1);
  assert.match(String(missingRevision.stderr), /--ui-revision/);

  const binaryWithoutRevision = spawnSync(process.execPath, [
    'deploy/manifest.mjs', '--ui-dist', files.ui, '--binary', files.binary, '--ui-revision', UI, '--out', files.manifest,
  ]);
  assert.equal(binaryWithoutRevision.status, 1);
  assert.match(String(binaryWithoutRevision.stderr), /--api-revision/);

  await rm(join(files.ui, 'index.html'));
  const notAUI = generate({ ...files, binary: undefined });
  assert.equal(notAUI.status, 1);
  assert.match(String(notAUI.stderr), /missing index\.html/);
});
