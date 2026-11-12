import { test } from 'node:test';
import assert from 'node:assert/strict';

const M = await import('../../src/features/scn-model.js');

test('breakdown lists each category with its count, skipping empty ones', () => {
  const rows = [
    { key: 'all', label: 'All Scenarios', n: 127 },
    { key: 'antivirus', label: 'Antivirus', n: 30 },
    { key: 'network', label: 'Network', n: 3 },
    { key: 'intel', label: 'Threat-Intel', n: 99 },
  ];
  assert.deepEqual(M.breakdownItems(rows), [
    { label: 'Antivirus', n: 30 },
    { label: 'Network', n: 3 },
    { label: 'Threat-Intel', n: 99 },
  ]);
});

test('breakdown is empty when there are no category rows', () => {
  assert.deepEqual(M.breakdownItems([{ key: 'all', label: 'All Scenarios', n: 0 }]), []);
  assert.deepEqual(M.breakdownItems(undefined), []);
});
