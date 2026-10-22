import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { scenarioSectionOrder, scenarioProductOf } = await load(['scenarioSectionOrder', 'scenarioProductOf']);

test('Scenarios sections appear in the agreed order with the agreed names', () => {
  const got = scenarioSectionOrder().map((s) => s.label);
  assert.deepEqual(got, [
    'Antivirus', 'WAF', 'Network', 'Email', 'DLP', 'Phishing', 'Kill Chain', 'Ransomware',
    'Web Gateway', 'Cloud', 'API BAS', 'AD BAS', 'Common', 'Threat-Intel',
  ]);
});

test('an AD scenario is shown in the AD BAS section, not under Common', () => {
  assert.equal(scenarioProductOf({ productLine: 'ad' }), 'ad');
  assert.equal(scenarioProductOf({ productLine: 'common' }), 'common');
});
