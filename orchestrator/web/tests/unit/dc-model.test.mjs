import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/dc-model.js';

const base = { name: 'Prod', enabled: true, autoVerify: false, verifyDelaySeconds: '120' };

test('every provider the server accepts has a definition', () => {
  assert.deepEqual(M.PROVIDERS.map((p) => p.id).sort(),
    ['crowdstrike', 'elastic', 'microsoft_defender', 'microsoft_sentinel', 'qradar', 'splunk', 'trellix']);
});

test('fieldsFor returns only the fields a provider uses', () => {
  assert.deepEqual(M.fieldsFor('microsoft_sentinel'), ['tenantId', 'clientId', 'clientSecret', 'workspaceId']);
  assert.deepEqual(M.fieldsFor('splunk'), ['baseUrl', 'apiToken', 'insecureTls']);
  assert.deepEqual(M.fieldsFor('nope'), []);
});

test('validate: a new connector needs its required fields and a name', () => {
  assert.match(M.validate('splunk', { ...base, name: '' }, null), /name/i);
  assert.match(M.validate('splunk', { ...base, baseUrl: '', apiToken: 't' }, null), /base URL/i);
  assert.match(M.validate('splunk', { ...base, baseUrl: 'https://s:8089', apiToken: '' }, null), /API token/i);
  assert.equal(M.validate('splunk', { ...base, baseUrl: 'https://s:8089', apiToken: 't' }, null), '');
  assert.match(M.validate('microsoft_sentinel', { ...base, tenantId: 't', clientId: 'c', clientSecret: 's', workspaceId: '' }, null), /workspace/i);
});

test('validate: Trellix needs no base URL (it has a default)', () => {
  assert.equal(M.validate('trellix', { ...base, baseUrl: '', apiToken: 't' }, null), '');
});

test('validate: editing keeps a stored secret when the field is left blank', () => {
  const existing = { provider: 'crowdstrike', hasClientSecret: true, hasApiToken: false };
  assert.equal(M.validate('crowdstrike', { ...base, baseUrl: 'https://api', clientId: 'c', clientSecret: '' }, existing), '');
  assert.match(M.validate('crowdstrike', { ...base, baseUrl: 'https://api', clientId: 'c', clientSecret: '' }, { hasClientSecret: false }), /client secret/i);
});

test('validate: Elastic takes an API key or a username and password, not both and not neither', () => {
  const e = { ...base, baseUrl: 'https://es:9200' };
  assert.match(M.validate('elastic', { ...e }, null), /API key|username/i);
  assert.match(M.validate('elastic', { ...e, apiToken: 'k', clientId: 'u', clientSecret: 'p' }, null), /either|not both/i);
  assert.match(M.validate('elastic', { ...e, clientId: 'u' }, null), /username and password/i);
  assert.equal(M.validate('elastic', { ...e, apiToken: 'k' }, null), '');
  assert.equal(M.validate('elastic', { ...e, clientId: 'u', clientSecret: 'p' }, null), '');
});

test('validate: delay must be a whole number of seconds from 0 to 3600', () => {
  const v = { ...base, baseUrl: 'https://s', apiToken: 't' };
  assert.match(M.validate('splunk', { ...v, verifyDelaySeconds: '-1' }, null), /delay/i);
  assert.match(M.validate('splunk', { ...v, verifyDelaySeconds: '9999' }, null), /delay/i);
  assert.match(M.validate('splunk', { ...v, verifyDelaySeconds: 'abc' }, null), /delay/i);
  assert.equal(M.validate('splunk', { ...v, verifyDelaySeconds: '0' }, null), '');
});

test('buildBody sends enabled explicitly (the server defaults a missing flag to disabled)', () => {
  const b = M.buildBody('splunk', { ...base, baseUrl: ' https://s:8089 ', apiToken: 'tok' }, null);
  assert.equal(b.enabled, true);
  assert.equal(b.provider, 'splunk');
  assert.equal(b.baseUrl, 'https://s:8089');
  assert.equal(b.verifyDelaySeconds, 120);
});

test('buildBody clears fields the provider does not use', () => {
  const b = M.buildBody('splunk', { ...base, baseUrl: 'https://s', apiToken: 't', tenantId: 'leftover', workspaceId: 'leftover', clientId: 'x' }, null);
  assert.equal(b.tenantId, '');
  assert.equal(b.workspaceId, '');
  assert.equal(b.clientId, '');
});

test('buildBody sends "***" for a stored secret left blank on edit, and the new value when typed', () => {
  const existing = { provider: 'crowdstrike', hasClientSecret: true, hasApiToken: false };
  const keep = M.buildBody('crowdstrike', { ...base, baseUrl: 'https://api', clientId: 'c', clientSecret: '' }, existing);
  assert.equal(keep.clientSecret, '***');
  const change = M.buildBody('crowdstrike', { ...base, baseUrl: 'https://api', clientId: 'c', clientSecret: 'new' }, existing);
  assert.equal(change.clientSecret, 'new');
  assert.equal(keep.apiToken, '', 'a secret the provider does not use is never "kept"');
});

test('buildBody on edit does not resend the provider', () => {
  const b = M.buildBody('splunk', { ...base, baseUrl: 'https://s', apiToken: '' }, { provider: 'splunk', hasApiToken: true });
  assert.equal('provider' in b, false);
});

test('rowSummary names the target the connector talks to', () => {
  assert.equal(M.rowSummary({ provider: 'splunk', baseUrl: 'https://s:8089' }), 'https://s:8089');
  assert.equal(M.rowSummary({ provider: 'microsoft_sentinel', tenantId: 'tt', workspaceId: 'ww' }), 'Workspace ww');
  assert.equal(M.rowSummary({ provider: 'microsoft_defender', tenantId: 'tt' }), 'Tenant tt');
  assert.equal(M.rowSummary({ provider: 'trellix', baseUrl: '' }), 'Default Trellix endpoint');
});

test('modeLabel says whether runs are verified on their own', () => {
  assert.equal(M.modeLabel({ enabled: false, autoVerify: true }), 'Disabled');
  assert.equal(M.modeLabel({ enabled: true, autoVerify: true }), 'Auto-verify');
  assert.equal(M.modeLabel({ enabled: true, autoVerify: false }), 'On demand');
});

test('canManage and canRun read the caller permissions', () => {
  assert.equal(M.canManage(['detectverify:configs:list']), true);
  assert.equal(M.canManage(['scenarios:run']), false);
  assert.equal(M.canManage(null), false);
  assert.equal(M.canRun(['detectverify:run']), true);
  assert.equal(M.canRun([]), false);
});

test('validate: editing an Elastic connector that already stores its credentials does not demand them again', () => {
  const e = { ...base, baseUrl: 'https://es:9200' };
  assert.equal(M.validate('elastic', { ...e }, { hasApiToken: true, hasClientSecret: false }), '', 'stored API key');
  assert.equal(M.validate('elastic', { ...e, clientId: 'u' }, { hasApiToken: false, hasClientSecret: true }), '', 'stored basic auth');
  assert.match(M.validate('elastic', { ...e, clientId: 'u' }, { hasApiToken: true, hasClientSecret: false }), /either|not both/i, 'adding basic on top of a stored key');
});
