import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('system services isolate identities, files and capabilities', async () => {
  for (const role of ['api', 'ui']) {
    const unit = await readFile(`deploy/lightning-driver-${role}.service.in`, 'utf8');
    for (const directive of [
      `User=lightning-driver-${role}`, `Group=lightning-driver-${role}`,
      'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes',
      'CapabilityBoundingSet=', 'AmbientCapabilities=', 'UMask=0077',
      'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', 'WantedBy=multi-user.target',
    ]) assert.ok(unit.split('\n').includes(directive), directive);
    assert.ok(unit.includes(role === 'api' ? 'ReadWritePaths=@STATE@' : 'InaccessiblePaths=@STATE@'));
    if (role === 'ui') assert.ok(!unit.includes('ReadWritePaths='));
  }
});
