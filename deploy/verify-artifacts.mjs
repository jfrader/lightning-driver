import { lstat, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  API_REPOSITORY,
  HEX_SHA256,
  UI_REPOSITORY,
  digest,
  filesIn,
  provenance,
  readTrustedManifest,
} from './artifact-manifest.mjs';

try {
  const [manifestPath, trustedDigest, uiRoot, binary] = process.argv.slice(2);
  const manifest = await readTrustedManifest(manifestPath, trustedDigest);
  provenance(manifest.ui, UI_REPOSITORY);
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
    provenance(manifest.api, API_REPOSITORY);
    if (!(await lstat(binary)).isFile() || !HEX_SHA256.test(manifest.api.sha256 ?? '') || digest(await readFile(binary)) !== manifest.api.sha256) {
      throw new Error('API integrity check failed');
    }
  }
} catch (error) {
  console.error(`artifact verification: ${error.message}`);
  process.exitCode = 1;
}
