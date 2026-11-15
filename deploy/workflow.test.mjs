import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('CI actions stay pinned with reviewable versions and read-only permissions', async () => {
  const workflow = await readFile('.github/workflows/ci.yml', 'utf8');
  const uses = [...workflow.matchAll(/uses:\s+(\S+)([^\n]*)/g)];
  assert.ok(uses.length > 0);
  for (const [, reference, comment] of uses) {
    assert.match(reference, /^[\w-]+\/[\w-]+@[a-f0-9]{40}$/);
    assert.match(comment, /# v\d+\.\d+\.\d+/);
  }
  assert.match(workflow, /permissions:\n  contents: read/);
  assert.match(workflow, /persist-credentials: false/);
});
