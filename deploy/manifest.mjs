#!/usr/bin/env node
// Generates the version-1 artifact manifest that `deploy/install.sh` verifies, and prints its
// SHA-256. Record that digest when you build and compare it at install time; a digest stored only
// beside the artifact is not provenance.
//
//   node deploy/manifest.mjs --ui-dist dist --ui-revision <40-hex> --out manifest.json
//   node deploy/manifest.mjs --ui-dist dist --ui-revision <40-hex> \
//     --binary release/api-server --api-revision <40-hex> --out manifest.json
import { writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import {
  API_REPOSITORY,
  REVISION,
  UI_REPOSITORY,
  digest,
  filesIn,
} from './artifact-manifest.mjs';

function fail(message) {
  console.error(`manifest: ${message}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const value = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const uiDist = value('--ui-dist');
const uiRevision = value('--ui-revision');
const binary = value('--binary');
const apiRevision = value('--api-revision');
const out = value('--out');

if (!uiDist || !uiRevision || !out) {
  fail('usage: node deploy/manifest.mjs --ui-dist DIR --ui-revision SHA --out FILE [--binary PATH --api-revision SHA]');
}
if (!REVISION.test(uiRevision)) fail('--ui-revision must be a full 40-character lowercase hex commit');
if (binary && !apiRevision) fail('--api-revision is required with --binary');
if (apiRevision && !binary) fail('--binary is required with --api-revision');
if (apiRevision && !REVISION.test(apiRevision)) fail('--api-revision must be a full 40-character lowercase hex commit');

const files = await filesIn(uiDist).catch((error) => fail(error.message));
const uiFiles = {};
for (const path of files) uiFiles[path] = digest(await readFile(`${uiDist}/${path}`));
if (!('index.html' in uiFiles)) fail('--ui-dist does not look like a built UI (missing index.html)');

const manifest = {
  version: 1,
  ui: { repository: UI_REPOSITORY, revision: uiRevision, files: uiFiles },
};
if (binary) manifest.api = { repository: API_REPOSITORY, revision: apiRevision, sha256: digest(await readFile(binary)) };

const body = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
await writeFile(out, body);
console.log(digest(body));
