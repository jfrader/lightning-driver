import { createHash } from 'node:crypto';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';

const HEX_SHA256 = /^[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

async function filesIn(root, prefix = '') {
  const files = [];
  for (const name of await readdir(join(root, prefix))) {
    const path = prefix ? `${prefix}/${name}` : name;
    const info = await lstat(join(root, path));
    if (info.isDirectory()) files.push(...await filesIn(root, path));
    else if (info.isFile()) files.push(path);
    else throw new Error(`artifact contains a symlink or special file: ${path}`);
  }
  return files.sort();
}

function provenance(artifact, repository) {
  if (artifact?.repository !== repository || !REVISION.test(artifact?.revision ?? '')) {
    throw new Error('missing or invalid artifact source provenance');
  }
}

try {
  const [manifestPath, trustedDigest, uiRoot, binary] = process.argv.slice(2);
  if (!HEX_SHA256.test(trustedDigest ?? '')) throw new Error('trusted manifest SHA-256 is required');
  const bytes = await readFile(manifestPath);
  if (digest(bytes) !== trustedDigest) throw new Error('manifest does not match trusted SHA-256');
  const manifest = JSON.parse(bytes);
  if (manifest.version !== 1) throw new Error('unsupported artifact manifest version');
  provenance(manifest.ui, 'https://github.com/jfrader/lightning-driver-ui');
  const files = await filesIn(uiRoot);
  const declared = Object.keys(manifest.ui.files ?? {}).sort();
  if (!files.includes('index.html') || JSON.stringify(files) !== JSON.stringify(declared)) {
    throw new Error('UI file inventory does not match trusted manifest');
  }
  for (const path of files) {
    const expected = manifest.ui.files[path];
    if (!HEX_SHA256.test(expected) || digest(await readFile(join(uiRoot, path))) !== expected) {
      throw new Error(`UI integrity check failed: ${path}`);
    }
  }
  if (binary) {
    provenance(manifest.api, 'https://github.com/jfrader/lightning-driver');
    if (!(await lstat(binary)).isFile() || !HEX_SHA256.test(manifest.api.sha256 ?? '') || digest(await readFile(binary)) !== manifest.api.sha256) {
      throw new Error('API integrity check failed');
    }
  }
} catch (error) {
  console.error(`artifact verification: ${error.message}`);
  process.exitCode = 1;
}
