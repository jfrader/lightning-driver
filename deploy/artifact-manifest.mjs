import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

/** The repositories an artifact manifest may claim provenance for. */
export const UI_REPOSITORY = 'https://github.com/jfrader/lightning-driver-ui';
export const API_REPOSITORY = 'https://github.com/jfrader/lightning-driver';

export const REVISION = /^[a-f0-9]{40}$/;
export const HEX_SHA256 = /^[a-f0-9]{64}$/;

export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** Every regular file under `root`, relative and sorted; a symlink or special file fails closed. */
export async function filesIn(root, prefix = '') {
  const files = [];
  for (const name of await readdir(join(root, prefix))) {
    const path = prefix ? `${prefix}/${name}` : name;
    const info = await lstat(join(root, path));
    if (info.isDirectory()) files.push(...(await filesIn(root, path)));
    else if (info.isFile()) files.push(path);
    else throw new Error(`artifact contains a symlink or special file: ${path}`);
  }
  return files.sort();
}

/** The artifact must name the expected repository and a full source revision. */
export function provenance(artifact, repository) {
  if (artifact?.repository !== repository || !REVISION.test(artifact?.revision ?? '')) {
    throw new Error('missing or invalid artifact source provenance');
  }
}

/** The trusted pin of one manifest: its SHA-256 and its parsed version-1 body. */
export async function readTrustedManifest(path, trustedDigest) {
  if (!HEX_SHA256.test(trustedDigest ?? '')) throw new Error('trusted manifest SHA-256 is required');
  const bytes = await readFile(path);
  if (digest(bytes) !== trustedDigest) throw new Error('manifest does not match trusted SHA-256');
  const manifest = JSON.parse(bytes);
  if (manifest.version !== 1) throw new Error('unsupported artifact manifest version');
  return manifest;
}
