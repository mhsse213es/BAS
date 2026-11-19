import { test } from 'node:test';
import assert from 'node:assert/strict';

const D = await import('../../src/features/scn-describe.js');

const CARBANAK = 'Eight-stage emulation of the group. Grounded in MITRE ATT&CK. KILL CHAIN STAGES: 1. Initial Access -- malspam-document child-process chain (T1566.001) 2. Persistence -- Windows service install (T1543.003) 3. Defense Evasion -- netsh firewall rule (T1686) ATTRIBUTION / CONFIDENCE: "confirmed" means two sources were cited. DOCUMENTED, NOT MODELED: Carbanak used a VBScript (T1102.002). ORDERING CAVEAT: a representative sequence. SAFETY: Stages 1, 3 are production-safe.';

test('splits the intro from the headed sections', () => {
  const d = D.parseDescription(CARBANAK);
  assert.equal(d.intro, 'Eight-stage emulation of the group. Grounded in MITRE ATT&CK.');
  assert.deepEqual(d.sections.map(s => s.title), ['KILL CHAIN STAGES', 'ATTRIBUTION / CONFIDENCE', 'DOCUMENTED, NOT MODELED', 'ORDERING CAVEAT', 'SAFETY']);
});

test('numbered stages become items, with a name and a detail split at the double dash', () => {
  const stages = D.parseDescription(CARBANAK).sections[0];
  assert.equal(stages.items.length, 3);
  assert.deepEqual(stages.items[0], { title: 'Initial Access', detail: 'malspam-document child-process chain (T1566.001)' });
  assert.equal(stages.items[2].title, 'Defense Evasion');
});

test('a section without numbers stays as paragraphs, and the double dash becomes an em dash', () => {
  const sec = D.parseDescription('Plain intro. SAFETY: Stage 1 -- safe.').sections[0];
  assert.equal(sec.items, undefined);
  assert.deepEqual(sec.paragraphs, ['Stage 1 — safe.']);
});

test('a description with no headings is one intro and no sections', () => {
  const d = D.parseDescription('Just a sentence about the scenario.');
  assert.equal(d.intro, 'Just a sentence about the scenario.');
  assert.deepEqual(d.sections, []);
});

test('empty input gives an empty intro and no sections', () => {
  assert.deepEqual(D.parseDescription(''), { intro: '', sections: [] });
  assert.deepEqual(D.parseDescription(null), { intro: '', sections: [] });
});
