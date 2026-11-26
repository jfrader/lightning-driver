import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('runtime secrets are ignored without hiding synthetic fixtures', () => {
  for (const path of [
    'config.toml', 'state/config.toml', 'deploy/docker/state/config.toml',
    'deploy/docker/.env', 'deploy/docker/lightning-driver-state.tar.gz',
    'runtime/anything', 'manager.sqlite', 'manager.sqlite-wal',
    'manager.sqlite-shm', 'manager.sqlite-journal', 'journal.db', 'journal.db-wal',
    'manager.sqlite.serve.lock', 'pending-invoice.key', 'lnd/admin.macaroon',
    'cln/access.rune', 'bitcoin/.cookie', 'lnd/client.pem',
  ]) assert.equal(spawnSync('git', ['check-ignore', '--no-index', path]).status, 0, path);
  for (const path of ['config.example.toml', 'api-server/tests/fixtures/synthetic.key', 'api-server/tests/fixtures/api-examples.json']) {
    assert.equal(spawnSync('git', ['check-ignore', '--no-index', path]).status, 1, path);
  }
});
