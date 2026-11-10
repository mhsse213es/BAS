import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/content-import-model.js';

test('resultRows labels each outcome plainly and never calls a non-emulable rule a draft', () => {
  const rows = M.resultRows([
    { title: 'A', emulable: true, draftId: 'd1', coverage: { emulated: ['sel'], notEmulated: [] } },
    { title: 'B', emulable: true, draftId: 'd1', duplicate: true, coverage: {} },
    { title: 'C', emulable: false, coverage: { notEmulated: ['ParentImage is not reproduced'] } },
    { title: 'D', error: 'not valid YAML' },
  ]);
  assert.deepEqual(rows.map(r => r.status), ['draft', 'already-waiting', 'not-emulable', 'error']);
  assert.match(rows[2].detail, /ParentImage/);
  assert.equal(rows[3].detail, 'not valid YAML');
  assert.equal(rows[0].draftId, 'd1');
  assert.equal(rows[2].draftId, undefined);
});

test('resultRows tolerates missing fields', () => {
  assert.deepEqual(M.resultRows(undefined), []);
  assert.equal(M.resultRows([{}])[0].status, 'not-emulable');
});

test('parseChainLines reads "scenario | step | run-if" lines, one-based steps, and reports every bad line', () => {
  const ok = M.parseChainLines('imp-sigma-a | 1\nimp-yara-b | 2 | prev_allowed\n\n  imp-x | 1 | prev_blocked  ');
  assert.deepEqual(ok.stages, [
    { scenarioId: 'imp-sigma-a', stepIndex: 0, runIf: '' },
    { scenarioId: 'imp-yara-b', stepIndex: 1, runIf: 'prev_allowed' },
    { scenarioId: 'imp-x', stepIndex: 0, runIf: 'prev_blocked' },
  ]);
  assert.deepEqual(ok.errors, []);

  const bad = M.parseChainLines('onlyid\nok | 0\nok | 1 | maybe\nok | x');
  assert.equal(bad.errors.length, 4);
  assert.match(bad.errors[0], /line 1/i);
  assert.match(bad.errors[2], /run-if/i);
});

test('commandPreview shows the first step command, shortened, and escapes nothing itself', () => {
  const d = { scenario: { steps: [{ command: 'x'.repeat(500), executor: 'cmd' }] } };
  const p = M.commandPreview(d);
  assert.equal(p.executor, 'cmd');
  assert.ok(p.text.length <= 301 && p.text.endsWith('…'));
  assert.deepEqual(M.commandPreview({}), { executor: '', text: '' });
});

test('statusLabel', () => {
  assert.equal(M.statusLabel('draft'), 'Awaiting review');
  assert.equal(M.statusLabel('approved'), 'Approved');
  assert.equal(M.statusLabel('weird'), 'weird');
});
