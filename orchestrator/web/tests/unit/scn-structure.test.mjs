import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';
import { structureDescription, verdictRows, chipItems, chunk } from '../../src/features/scn-structure.js';
import { describeHtml, inlineHtml } from '../../src/features/scn-overview.js';

// Shapes taken from real scenario descriptions: aligned stage lines with sub-stages, "- " tiers, an aligned verdict
// legend, "KEY   text" rows, a Safety-first description with inline bullets, and "Lab-only." prose.
const AKIRA = `Stage-based emulation of the Akira chain. Ransomware-grade but safe.
KILL CHAIN STAGES:
  1.  Initial Access                 — RDP/NLA exposure posture check (T1021.001)
  3b. Credential Access (supp.)      — LSASS access-mask probe (T1003.001, read-only)
  8.  Recovery Inhibition B          — VSS deletion via WMI
      Win32_ShadowCopy.Delete() (T1490, lab-only)

SAFETY: No real encryption of user data. XOR is applied to one temp file only.
`;
const TIERS = `Campaign-grade emulation of APT36.
TIERS: - Posture (default, safe anywhere): validates defences across layers
  and detection layers.
- Telemetry (opt-in, production-safe under approval): real, data-safe execution.
- Lab (opt-in, isolated range only): full-fidelity tradecraft.

GUARDRAILS: no domain-controller interlock. Per-OS: Windows only. SAFETY: no real egress.
`;
const VERDICTS = `Runs the DLL hijack chain.
Expected verdicts:
  PASS  = EDR/SIEM detected the hijack execution (or, for Step 4, the
          ACL enumeration)
  FAIL  = the technique executed without generating an alert
  SKIP  = a required payload is missing from this deployment
`;
const DEFS = `Read-only ADCS audit, one step per escalation class (T1649).
  ESC1  enrollee-supplied subject, client-auth EKU
  ESC4  template ACL grants write rights to a non-tier-0 principal
Not assessed by this scenario: ESC8 and ESC10. SAFETY: reads configuration only.
`;
const SAFETY_FIRST = `SAFETY: the USB and print steps change host state. Run this on a lab endpoint.
Combines every DLP channel into one scenario. Uses five local channels.
Two models are present: - The five native channels are local-only.
  never a full verdict.
- The four network channels are sink-verified.
`;
const LAB = 'Lab-only. Checks that an account holding SELECT only cannot change data. The agent seeds a fixture. It then tries one INSERT, e.g. a fixed row. Afterwards it cleans up.';

test('a stage list keeps its numbers, splits name from detail, and joins wrapped lines', () => {
  const d = structureDescription(AKIRA);
  assert.equal(d.lead, 'Stage-based emulation of the Akira chain.');
  assert.deepEqual(d.body, ['Ransomware-grade but safe.']);
  const st = d.sections.find((s) => s.kind === 'stages');
  assert.deepEqual(st.items.map((i) => i.n), ['1', '3b', '8']);
  assert.deepEqual(st.items[1], { n: '3b', title: 'Credential Access (supp.)', detail: 'LSASS access-mask probe (T1003.001, read-only)' });
  assert.match(st.items[2].detail, /Win32_ShadowCopy\.Delete\(\) \(T1490, lab-only\)/);
  assert.equal(d.sections.find((s) => s.kind === 'safety').paras[0], 'No real encryption of user data. XOR is applied to one temp file only.');
});

test('tiers become named bullets and the line after them starts a new section', () => {
  const d = structureDescription(TIERS);
  const t = d.sections.find((s) => s.kind === 'tiers');
  assert.deepEqual(t.bullets.map((b) => b.name), ['Posture (default, safe anywhere)', 'Telemetry (opt-in, production-safe under approval)', 'Lab (opt-in, isolated range only)']);
  assert.match(t.bullets[0].text, /defences across layers and detection layers\./);
  assert.deepEqual(d.sections.map((s) => s.title), ['Tiers', 'Guardrails', 'Per-OS', 'Safety']);
});

test('an aligned verdict legend becomes verdict rows', () => {
  const v = structureDescription(VERDICTS).sections[0];
  assert.equal(v.kind, 'verdicts');
  assert.deepEqual(v.verdicts.map((r) => r.verdict), ['PASS', 'FAIL', 'SKIP']);
  assert.match(v.verdicts[0].text, /ACL enumeration\)$/);
});

test('verdictRows needs at least two verdicts, and chipItems only plain short lists', () => {
  assert.equal(verdictRows('PASS = fine'), null);
  assert.equal(verdictRows('PASS = held; FAIL = did not; ERROR = could not run').length, 3);
  assert.deepEqual(chipItems('USB copy, clipboard, print spool and archive staging.'), ['USB copy', 'clipboard', 'print spool', 'archive staging']);
  assert.equal(chipItems('one sentence about things'), null);
});

test('KEY   text rows become definitions and a Not assessed note is kept', () => {
  const d = structureDescription(DEFS);
  assert.equal(d.sections[0].title, 'Details');
  assert.deepEqual(d.sections[0].defs.map((r) => r.key), ['ESC1', 'ESC4']);
  assert.ok(d.sections.some((s) => s.title === 'Not assessed by this scenario' || s.title === 'Not assessed'));
});

test('a description that opens with Safety still gets its lead from the next paragraph, and inline bullets split out', () => {
  const d = structureDescription(SAFETY_FIRST);
  assert.equal(d.lead, 'Combines every DLP channel into one scenario.');
  assert.ok(d.sections.some((s) => s.kind === 'safety'), 'the Safety section is kept');
  const list = d.sections.find((s) => s.bullets.length === 2);
  assert.ok(list, 'the two inline bullets become a list');
  assert.match(list.bullets[0].text, /native channels are local-only\. never a full verdict\./);
  assert.ok(d.body.some((b) => /Two models are present:/.test(b)));
});

test('Lab-only becomes a badge and does not stay in the text; e.g. does not end a sentence', () => {
  const d = structureDescription(LAB);
  assert.deepEqual(d.badges, [{ label: 'Lab only', tone: 'warn' }]);
  assert.equal(d.lead, 'Checks that an account holding SELECT only cannot change data.');
  assert.ok(d.body.join(' ').includes('e.g. a fixed row'));
});

test('empty and missing input structure to nothing', () => {
  for (const v of ['', null, undefined, '   \n  ']) {
    assert.deepEqual(structureDescription(v), { badges: [], lead: '', body: [], sections: [] });
  }
});

test('a long run-on is cut at semicolons, never lost', () => {
  const t = Array.from({ length: 14 }, (_, i) => `step number ${i} does a fixed thing that is described at some length`).join('; ') + '.';
  const parts = chunk(t, 300);
  assert.ok(parts.length > 1);
  assert.equal(parts.join(' ').replace(/\s+/g, ' '), t);
});

// The Overview must never drop words: every word of the stored text appears in what is rendered.
function words(s) { return String(s).toLowerCase().match(/[a-z0-9][a-z0-9_.()/-]{3,}/g) || []; }
test('rendering keeps every word of every shape', () => {
  setupDom();
  for (const raw of [AKIRA, TIERS, VERDICTS, DEFS, SAFETY_FIRST, LAB]) {
    const box = document.createElement('div');
    box.innerHTML = describeHtml(raw);
    // textContent glues neighbouring blocks together, so put a space where every tag was before reading the words.
    const flat = document.createElement('div'); flat.innerHTML = box.innerHTML.replace(/<\/?code[^>]*>/g, '').replace(/<[^>]+>/g, ' ');
    const have = new Set(words(flat.textContent));
    const lost = [...new Set(words(raw))].filter((w) => !have.has(w) && !/^(?:\d+[a-z]?\.?)$/.test(w) && !/^(?:lab|posture|read|telemetry)-only\.$/.test(w)); // a leading tag is shown as a badge
    assert.deepEqual(lost, [], 'words missing from the rendered overview for: ' + raw.slice(0, 40));
  }
});

test('the rendered overview has a hero, section cards, a timeline and verdict pills', () => {
  setupDom();
  const a = document.createElement('div'); a.innerHTML = describeHtml(AKIRA);
  assert.ok(a.querySelector('.ov-hero .ov-lead'));
  assert.equal(a.querySelectorAll('.ov-stages li').length, 3);
  assert.equal(a.querySelectorAll('.ov-stages li.sub').length, 1, 'a lettered stage is drawn as a sub-stage');
  assert.ok(a.querySelector('.ov-card.k-safety'));
  const v = document.createElement('div'); v.innerHTML = describeHtml(VERDICTS);
  assert.deepEqual([...v.querySelectorAll('.ov-verdict .ov-v')].map((e) => e.textContent), ['PASS', 'FAIL', 'SKIP']);
});

test('inline formatting marks technique ids, verdict words and code names, and escapes the rest', () => {
  const h = inlineHtml('FAIL when T1003.001 reads pg_write_server_files <b>x</b>');
  assert.match(h, /<span class="ov-v ov-bad">FAIL<\/span>/);
  assert.match(h, /<code class="ov-tech">T1003\.001<\/code>/);
  assert.match(h, /<code class="ov-code">pg_write_server_files<\/code>/);
  assert.match(h, /&lt;b&gt;x&lt;\/b&gt;/);
  assert.doesNotMatch(h, /<b>/);
});

test('"Read-only audit of ..." is prose, but "Read-only. Checks ..." is a tag', () => {
  assert.deepEqual(structureDescription('Read-only ADCS audit, one step per class.').badges, []);
  assert.match(structureDescription('Read-only ADCS audit, one step per class.').lead, /^Read-only ADCS audit/);
  assert.deepEqual(structureDescription('Read-only. Lists the accounts.').badges, [{ label: 'Read only', tone: 'ok' }]);
});

test('definition rows with a single space after a coded key stay separate rows', () => {
  const d = structureDescription('Audit.\n  ESC1  first row text\n  ESC9  ninth row\n  ESC11 eleventh row\n  ESC13 thirteenth row\nDone.');
  assert.deepEqual(d.sections[0].defs.map((r) => r.key), ['ESC1', 'ESC9', 'ESC11', 'ESC13']);
});

test('a run-on is not cut inside brackets', () => {
  const t = 'It does a thing (these are the ONLY statements carrying it; the baseline read and fingerprints carry the other tag) and ' + 'then continues with more detail; '.repeat(14) + 'finally ends.';
  const parts = chunk(t, 300);
  assert.ok(parts.every((p) => (p.match(/\(/g) || []).length === (p.match(/\)/g) || []).length), 'every part has balanced brackets');
});

import { cap } from '../../src/features/scn-structure.js';
test('cap capitalises a plain leading word and leaves code-like starts alone', () => {
  assert.equal(cap('the USB step changes state.'), 'The USB step changes state.');
  assert.equal(cap('sftp.exe is missing'), 'sftp.exe is missing');
  assert.equal(cap('pg_read_all_data is held'), 'pg_read_all_data is held');
  assert.equal(cap('SKIP is reported'), 'SKIP is reported');
  assert.equal(structureDescription('Intro.\nSAFETY: reads configuration only.').sections[0].paras[0], 'Reads configuration only.');
});
