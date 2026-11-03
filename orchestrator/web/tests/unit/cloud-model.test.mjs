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
