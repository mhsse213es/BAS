import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scenarioCards, buildCloudRunRequest, describeRunError, runTone, cloudProviderLabel } from '../../src/features/cloud-model.js';

test('scenarioCards accepts the envelope and sorts by provider then name', function() {
  var cards = scenarioCards({ scenarios: [
    { id: 'b', name: 'Zeta', provider: 'gcp', steps: [{}, {}] },
    { id: 'a', name: 'Alpha', provider: 'aws', steps: [{}] },
    { id: 'c', name: 'Beta', provider: 'aws', steps: [] },
  ] });
  assert.deepEqual(cards.map(function(c) { return c.id; }), ['a', 'c', 'b']);
  assert.equal(cards[0].providerLabel, 'AWS');
  assert.equal(cards[0].stepCount, 1);
});

test('scenarioCards accepts a bare array and drops entries without an id', function() {
  var cards = scenarioCards([{ id: 'x', name: 'X', provider: 'azure' }, { name: 'no id' }, null]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].providerLabel, 'Azure');
  assert.equal(cards[0].stepCount, 0);
});

test('scenarioCards tolerates a missing catalogue', function() {
  assert.deepEqual(scenarioCards(undefined), []);
  assert.deepEqual(scenarioCards({}), []);
});

test('buildCloudRunRequest sends only the fields the server reads, trimmed', function() {
  var r = buildCloudRunRequest({ scenarioId: ' s1 ', provider: 'aws', accountId: ' 111 ', principal: ' arn:p ', resource: ' arn:r ', region: 'eu-west-1', extra: 'ignored' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.body, {
    scenarioId: 's1',
    account: { provider: 'aws', accountId: '111', region: 'eu-west-1' },
    principal: 'arn:p',
    resource: 'arn:r',
  });
});

test('buildCloudRunRequest omits an empty region', function() {
  var r = buildCloudRunRequest({ scenarioId: 's', provider: 'gcp', accountId: 'proj', principal: 'p', resource: 'r', region: '  ' });
  assert.equal(r.ok, true);
  assert.equal('region' in r.body.account, false);
});

test('buildCloudRunRequest names the first missing field', function() {
  assert.match(buildCloudRunRequest({}).error, /scenario/);
  assert.match(buildCloudRunRequest({ scenarioId: 's' }).error, /provider/);
  assert.match(buildCloudRunRequest({ scenarioId: 's', provider: 'oci', accountId: '1' }).error, /provider/);
  assert.match(buildCloudRunRequest({ scenarioId: 's', provider: 'aws' }).error, /account ID/);
  assert.match(buildCloudRunRequest({ scenarioId: 's', provider: 'aws', accountId: '1' }).error, /principal/);
  assert.match(buildCloudRunRequest({ scenarioId: 's', provider: 'aws', accountId: '1', principal: 'p' }).error, /resource/);
});

test('describeRunError explains a 403 as the allow-list refusal', function() {
  assert.match(describeRunError(403, 'account is not on the server’s cloud allow-list'), /allow-list/);
});

test('describeRunError explains busy and saturated responses', function() {
  assert.match(describeRunError(409, ''), /already running/);
  assert.match(describeRunError(503, ''), /limit|not configured/);
});

test('describeRunError shows the server message for a 400, and a fallback otherwise', function() {
  assert.equal(describeRunError(400, 'principal is not in the graph'), 'principal is not in the graph');
  assert.equal(describeRunError(500, ''), 'The request failed (HTTP 500).');
});

test('runTone maps statuses and leaves unknown ones neutral', function() {
  assert.equal(runTone('completed'), 'ok');
  assert.equal(runTone('partial'), 'warn');
  assert.equal(runTone('failed'), 'bad');
  assert.equal(runTone('running'), 'neutral');
  assert.equal(runTone(undefined), 'neutral');
});

test('cloudProviderLabel falls back to the raw key', function() {
  assert.equal(cloudProviderLabel('gcp'), 'GCP');
  assert.equal(cloudProviderLabel('oci'), 'oci');
  assert.equal(cloudProviderLabel(undefined), '');
});

import { parseHeldIdentities, buildDiscoveryRunRequest, runRow, runRows } from '../../src/features/cloud-model.js';

test('parseHeldIdentities splits on commas, spaces and new lines and drops blanks', function() {
  assert.deepEqual(parseHeldIdentities(' a,b  c\n\nd , '), ['a', 'b', 'c', 'd']);
  assert.deepEqual(parseHeldIdentities(''), []);
  assert.deepEqual(parseHeldIdentities(undefined), []);
});

test('buildDiscoveryRunRequest sends discover true with the target and held identities', function() {
  var r = buildDiscoveryRunRequest({ label: ' audit ', provider: 'aws', accountId: '111', region: 'us-east-1', target: ' arn:t ', held: 'arn:a, arn:b' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.body, {
    scenarioId: 'audit',
    account: { provider: 'aws', accountId: '111', region: 'us-east-1' },
    discover: true,
    target: 'arn:t',
    held: ['arn:a', 'arn:b'],
  });
});

test('buildDiscoveryRunRequest does not send maxHops, leaving the server default', function() {
  var r = buildDiscoveryRunRequest({ label: 'x', provider: 'gcp', accountId: 'p', target: 't' });
  assert.equal(r.ok, true);
  assert.equal('maxHops' in r.body, false);
  assert.deepEqual(r.body.held, []);
});

test('buildDiscoveryRunRequest names the first missing field', function() {
  assert.match(buildDiscoveryRunRequest({}).error, /label/);
  assert.match(buildDiscoveryRunRequest({ label: 'x' }).error, /provider/);
  assert.match(buildDiscoveryRunRequest({ label: 'x', provider: 'aws' }).error, /account ID/);
  assert.match(buildDiscoveryRunRequest({ label: 'x', provider: 'aws', accountId: '1' }).error, /target/);
});

test('runRow maps a run to display fields and a tone', function() {
  var row = runRow({ id: 'r1', scenarioId: 'audit', provider: 'azure', accountId: 'sub', status: 'partial', error: '', initiatedBy: 'u1', startedAt: '2026-11-03T10:00:00Z' });
  assert.equal(row.account, 'Azure sub');
  assert.equal(row.tone, 'warn');
  assert.equal(row.label, 'audit');
});

test('runRow tolerates missing fields', function() {
  var row = runRow({ id: 'r2' });
  assert.equal(row.status, 'unknown');
  assert.equal(row.tone, 'neutral');
  assert.equal(row.account, '');
});

test('runRows keeps only rows with an id and sorts newest first', function() {
  var rows = runRows([
    { id: 'old', startedAt: '2026-11-01T00:00:00Z' },
    { startedAt: '2026-11-09T00:00:00Z' },
    { id: 'new', startedAt: '2026-11-09T00:00:00Z' },
  ]);
  assert.deepEqual(rows.map(function(r) { return r.id; }), ['new', 'old']);
});

test('runRows tolerates a non-array response', function() {
  assert.deepEqual(runRows(null), []);
  assert.deepEqual(runRows({ error: 'x' }), []);
});
