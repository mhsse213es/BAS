import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';
import { techniqueIndex, filterIndex, cleanDescription, safeMitreUrl } from '../../src/features/scn-techniques-model.js';

const matrix = { tactics: [
  { id: 'execution', name: 'Execution', techniques: [{ id: 'T1059', name: 'Command and Scripting Interpreter' }] },
  { id: 'credential-access', name: 'Credential Access', techniques: [{ id: 'T1003', name: 'OS Credential Dumping' }, { id: 'T1558.003', name: 'Kerberoasting' }] },
  { id: 'persistence', name: 'Persistence', techniques: [{ id: 'T1053', name: 'Scheduled Task/Job' }] },
] };
const scenarios = [
  { id: 's1', name: 'Cred dump', steps: [{ techniqueId: 'T1003' }, { techniqueId: 'T1059' }] },
  { id: 's2', name: 'Kerb', steps: [{ techniqueId: 'T1558.003' }, { techniqueId: 'T1003' }], artTechniques: ['T9999'] },
];

test('the index groups by tactic in dataset order, counts scenarios, and keeps unknown ids apart', () => {
  const i = techniqueIndex({ scenarios, matrix });
  assert.equal(i.total, 4);
  assert.deepEqual(i.tactics.map((t) => t.name), ['Execution', 'Credential Access']);
  const dump = i.tactics[1].items.find((t) => t.id === 'T1003');
  assert.equal(dump.count, 2);
  assert.deepEqual(i.unknown, [{ id: 'T9999', count: 1 }]);
  assert.equal(i.tactics.flatMap((t) => t.items).some((t) => t.id === 'T1053'), false, 'unused techniques are not listed');
});

test('a technique in two tactics is listed under both but counted once', () => {
  const m = { tactics: [{ id: 'a', name: 'A', techniques: [{ id: 'T1', name: 'One' }] }, { id: 'b', name: 'B', techniques: [{ id: 'T1', name: 'One' }] }] };
  const i = techniqueIndex({ scenarios: [{ id: 's', steps: [{ techniqueId: 'T1' }] }], matrix: m });
  assert.equal(i.total, 1);
  assert.equal(i.tacticCount, 2);
});

test('search matches id or name and drops empty groups', () => {
  const f = filterIndex(techniqueIndex({ scenarios, matrix }), 'kerb');
  assert.deepEqual(f.tactics.map((t) => t.items.map((i) => i.id)), [['T1558.003']]);
  assert.equal(filterIndex(techniqueIndex({ scenarios, matrix }), 'zzz').tactics.length, 0);
});

test('MITRE citation and link markup is removed from descriptions', () => {
  assert.equal(cleanDescription('Adversaries dump [credentials](https://x.y/z) (Citation: Foo 2020) from memory.'), 'Adversaries dump credentials from memory.');
});

test('only attack.mitre.org links are offered as links', () => {
  assert.equal(safeMitreUrl('https://attack.mitre.org/techniques/T1003'), 'https://attack.mitre.org/techniques/T1003');
  assert.equal(safeMitreUrl('javascript:alert(1)'), '');
  assert.equal(safeMitreUrl('https://evil.example/attack.mitre.org/'), '');
});

async function render(html) {
  setupDom();
  const d = document.createElement('div');
  d.innerHTML = html;
  return d;
}

test('the list shows each technique as a button with its id, name and scenario count', async () => {
  setupDom();
  const { techniqueListHtml } = await load(['techniqueListHtml']);
  const d = await render(techniqueListHtml(techniqueIndex({ scenarios, matrix }), ''));
  assert.match(d.textContent, /4 techniques across 2 tactics/);
  const row = [...d.querySelectorAll('button.tt-row')].find((b) => b.textContent.includes('T1003'));
  assert.match(row.textContent, /OS Credential Dumping/);
  assert.match(row.textContent, /2 scenarios/);
  assert.match(d.textContent, /Not in the ATT&CK dataset/);
});

test('the detail shows MITRE content, escapes it, and links only to MITRE', async () => {
  setupDom();
  const { techniqueDetailHtml } = await load(['techniqueDetailHtml']);
  const d = await render(techniqueDetailHtml({
    id: 'T1003', name: 'OS Credential Dumping', tactics: ['credential-access'], platforms: ['Windows'],
    description: 'Dump <img src=x onerror=alert(1)> creds. (Citation: A)', detection: 'Watch LSASS access.',
    mitigations: [{ name: 'Privileged Account Management', desc: 'Limit admins.' }], groups: ['APT29'],
    url: 'javascript:alert(1)',
  }, [{ id: 's1', name: 'Cred dump' }]));
  assert.match(d.textContent, /OS Credential Dumping/);
  assert.match(d.textContent, /Watch LSASS access/);
  assert.match(d.textContent, /Privileged Account Management/);
  assert.match(d.textContent, /APT29/);
  assert.match(d.textContent, /Cred dump/);
  assert.equal(d.querySelector('img'), null);
  assert.equal(d.querySelector('a'), null, 'a non-MITRE url is not a link');
  assert.doesNotMatch(d.textContent, /Citation/);
});

test('the Scenarios banner makes ATT&CK Techniques a real button wired to the panel', async () => {
  setupDom();
  const { mountPageHeroes } = await load(['mountPageHeroes']);
  mountPageHeroes();
  const b = document.getElementById('sc-hs-tech').closest('button');
  assert.ok(b, 'the stat is inside a button');
  assert.equal(b.getAttribute('data-on-click'), 'openTechniqueCatalog');
  assert.equal(document.getElementById('sc-hs-total').closest('button'), null, 'other stats stay plain');
});
